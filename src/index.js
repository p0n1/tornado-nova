/* eslint-disable no-console */
const MerkleTree = require('fixed-merkle-tree')
const { ethers } = require('hardhat')
const { BigNumber } = ethers
const { toFixedHex, poseidonHash2, getExtDataHash, FIELD_SIZE, shuffle, debugLog } = require('./utils')
const Utxo = require('./utxo')

const { prove } = require('./prover')
const MERKLE_TREE_HEIGHT = 5

async function buildMerkleTree({ tornadoPool }) {
  const filter = tornadoPool.filters.NewCommitment()
  const events = await tornadoPool.queryFilter(filter, 0)

  const leaves = events.sort((a, b) => a.args.index - b.args.index).map((e) => toFixedHex(e.args.commitment))
  return new MerkleTree(MERKLE_TREE_HEIGHT, leaves, { hashFunction: poseidonHash2 })
}

async function getProof({
  asset,
  inputs,
  outputs,
  tree,
  extAmount,
  fee,
  recipient,
  relayer,
  isL1Withdrawal,
  l1Fee,
  tokenOut,
  amountOutMin,
  swapRecipient,
  swapRouter,
  swapData,
  transactData,
}) {
  debugLog("----------getProof start----------")
  debugLog("getProof> asset", asset)
  inputs = shuffle(inputs)
  outputs = shuffle(outputs)

  let inputMerklePathIndices = []
  let inputMerklePathElements = []

  for (const input of inputs) {
    if (input.amount > 0) {
      input.index = tree.indexOf(toFixedHex(input.getCommitment()))
      if (input.index < 0) {
        throw new Error(`Input commitment ${toFixedHex(input.getCommitment())} was not found`)
      }
      inputMerklePathIndices.push(input.index)
      inputMerklePathElements.push(tree.path(input.index).pathElements)
    } else {
      inputMerklePathIndices.push(0)
      inputMerklePathElements.push(new Array(tree.levels).fill(0))
    }
  }

  // address tokenOut;
  // uint256 amountOutMin;
  // address swapRecipient;
  // address swapRouter;
  // bytes swapData;
  // bytes transactData;

  const extData = {
    recipient: toFixedHex(recipient, 20),
    extAmount: toFixedHex(extAmount),
    relayer: toFixedHex(relayer, 20),
    fee: toFixedHex(fee),
    encryptedOutput1: outputs[0].encrypt(),
    encryptedOutput2: outputs[1].encrypt(),
    isL1Withdrawal,
    l1Fee,
    tokenOut: toFixedHex(tokenOut, 20),
    amountOutMin: toFixedHex(amountOutMin),
    swapRecipient: toFixedHex(swapRecipient, 20),
    swapRouter: toFixedHex(swapRouter, 20),
    swapData: swapData,
    transactData: transactData,
  }

  // Check if extAmount is not zero. If so, set publicAsset to asset to enable onchain transfer and disable privacy for asset type.
  let publicAsset = 0 // TODO: default to zero or magic number. zero is friendly for all old tests. magic number is more secure.
  if (extAmount != 0) {
    publicAsset = asset
    console.log("getProof> extAmount is %s, expose publicAsset: %s", extAmount, publicAsset)
  } else {
    console.log("getProof> extAmount == 0, do not expose publicAsset")
  }

  const extDataHash = getExtDataHash(extData)
  let input = {
    root: tree.root(),
    inputNullifier: inputs.map((x) => x.getNullifier()),
    outputCommitment: outputs.map((x) => x.getCommitment()),
    publicAmount: BigNumber.from(extAmount).sub(fee).add(FIELD_SIZE).mod(FIELD_SIZE).toString(),
    publicAsset, // public input
    extDataHash,

    asset: BigNumber.from(asset), // private input

    // data for 2 transaction inputs
    inAmount: inputs.map((x) => x.amount),
    inPrivateKey: inputs.map((x) => x.keypair.privkey),
    inBlinding: inputs.map((x) => x.blinding),
    inPathIndices: inputMerklePathIndices,
    inPathElements: inputMerklePathElements,

    // data for 2 transaction outputs
    outAmount: outputs.map((x) => x.amount),
    outBlinding: outputs.map((x) => x.blinding),
    outPubkey: outputs.map((x) => x.keypair.pubkey),
  }

  const proof = await prove(input, `./artifacts/circuits/transaction${inputs.length}`)

  const args = {
    proof,
    root: toFixedHex(input.root),
    inputNullifiers: inputs.map((x) => toFixedHex(x.getNullifier())),
    outputCommitments: outputs.map((x) => toFixedHex(x.getCommitment())),
    publicAmount: toFixedHex(input.publicAmount),
    publicAsset: toFixedHex(input.publicAsset, 20),
    extDataHash: toFixedHex(extDataHash),
  }

  debugLog('getProof> input', input)
  debugLog('getProof> Solidity args', args)
  debugLog('getProof> extData', extData)
  debugLog("----------getProof end----------")
  return {
    extData,
    args,
  }
}

async function prepareTransaction({
  tornadoPool,
  asset = 0,
  inputs = [],
  outputs = [],
  fee = 0,
  recipient = 0,
  relayer = 0,
  isL1Withdrawal = false,
  l1Fee = 0,
  tokenOut = 0,
  amountOutMin = 0,
  swapRecipient = 0,
  swapRouter = 0,
  swapData = 0,
  transactData = 0,
}) {
  debugLog("----------prepareTransaction start----------")
  console.log("prepareTransaction> asset", asset)
  if (inputs.length > 16 || outputs.length > 2) {
    throw new Error('Incorrect inputs/outputs count')
  }
  while (inputs.length !== 2 && inputs.length < 16) {
    inputs.push(new Utxo({asset: asset}))
  }
  while (outputs.length < 2) {
    outputs.push(new Utxo({asset: asset}))
  }

  let extAmount = BigNumber.from(fee)
    .add(outputs.reduce((sum, x) => sum.add(x.amount), BigNumber.from(0)))
    .sub(inputs.reduce((sum, x) => sum.add(x.amount), BigNumber.from(0)))

  const { args, extData } = await getProof({
    asset,
    inputs,
    outputs,
    tree: await buildMerkleTree({ tornadoPool }),
    extAmount,
    fee,
    recipient,
    relayer,
    isL1Withdrawal,
    l1Fee,
    tokenOut,
    amountOutMin,
    swapRecipient,
    swapRouter,
    swapData,
    transactData,
  })
  debugLog("----------prepareTransaction end----------")
  return {
    args,
    extData,
  }
}

async function transaction({ tornadoPool, ...rest }) {
  const { args, extData } = await prepareTransaction({
    tornadoPool,
    ...rest,
  })

  const receipt = await tornadoPool.transact(args, extData, {
    gasLimit: 2e6,
  })
  return await receipt.wait()
}

async function swapTransaction({ tornadoPool, ...rest }) {
  const { args, extData } = await prepareTransaction({
    tornadoPool,
    ...rest,
  })

  const receipt = await tornadoPool.transactAndSwap(args, extData, {
    gasLimit: 4e6,
  })
  return await receipt.wait()
}

async function registerAndTransact({ tornadoPool, account, ...rest }) {
  const { args, extData } = await prepareTransaction({
    tornadoPool,
    ...rest,
  })

  const receipt = await tornadoPool.registerAndTransact(account, args, extData, {
    gasLimit: 2e6,
  })
  await receipt.wait()
}

module.exports = { transaction, swapTransaction, registerAndTransact, prepareTransaction, buildMerkleTree }
