const { ethers } = require('hardhat')

const abi = new ethers.utils.AbiCoder()

function encodeDataForBridge({ proof, extData }) {
  return abi.encode(
    [
      'tuple(bytes proof,bytes32 root,bytes32[] inputNullifiers,bytes32[2] outputCommitments,uint256 publicAmount,uint256 publicAsset,bytes32 extDataHash)',
      'tuple(address recipient,int256 extAmount,address relayer,uint256 fee,bytes encryptedOutput1,bytes encryptedOutput2,bool isL1Withdrawal,uint256 l1Fee,address tokenOut,uint256 amountOutMin,address swapRecipient,address swapRouter,bytes swapData,bytes transactData)',
    ],
    [proof, extData],
  )
}

module.exports = { encodeDataForBridge }
