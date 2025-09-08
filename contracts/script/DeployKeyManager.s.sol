// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {KeyManager} from "../src/KeyManager.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployKeyManager
/// @notice Simple script to deploy KeyManager implementation and proxy, then initialize
contract DeployKeyManager is Script {
    function run() external returns (address, address) {
        // Get the manager address from environment variable or use sender as fallback
        address manager = vm.envOr("MANAGER_ADDRESS", msg.sender);

        vm.startBroadcast();

        // Deploy the KeyManager implementation
        KeyManager implementation = new KeyManager();
        console.log("KeyManager implementation deployed at:", address(implementation));

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(KeyManager.initialize.selector, manager);

        // Deploy the proxy and initialize it
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        console.log("ERC1967Proxy deployed at:", address(proxy));

        // Verify initialization
        KeyManager proxyContract = KeyManager(address(proxy));
        require(proxyContract.manager() == manager, "Manager not set correctly");

        console.log("Deployment successful!");
        console.log("Implementation:", address(implementation));
        console.log("Proxy:", address(proxy));
        console.log("Manager:", manager);

        vm.stopBroadcast();

        return (address(proxy), address(implementation));
    }
}
