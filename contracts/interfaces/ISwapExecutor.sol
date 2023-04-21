pragma solidity ^0.7.0;

interface ISwapExecutor {
    function executeSwap(
        address _tokenIn,
        address _tokenOut,
        uint256 _amountIn,
        uint256 _amountOutMin,
        address _swapRouter,
        address _swapRecipient,
        bytes calldata _swapData,
        bytes calldata _transactData
    ) external;
}