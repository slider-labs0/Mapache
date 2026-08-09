// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Vault - simple ETH deposit/withdraw vault
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraw your full balance.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // Send the funds back to the caller.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        // Then zero out their balance.
        balances[msg.sender] = 0;
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}
