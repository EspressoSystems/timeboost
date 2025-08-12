// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {KeyManager} from "../src/KeyManager.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract KeyManagerTest is Test {
    KeyManager public keyManagerProxy;
    address public manager;
    address public owner;

    function setUp() public {
        owner = makeAddr("owner");
        manager = makeAddr("manager");
        KeyManager keyManagerImpl = new KeyManager();
        bytes memory data = abi.encodeWithSelector(KeyManager.initialize.selector, manager);
        vm.prank(owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(keyManagerImpl), data);
        keyManagerProxy = KeyManager(address(proxy));
    }

    function test_setThresholdEncryptionKey() public {
        bytes memory thresholdEncKey = abi.encodePacked("1");
        vm.prank(manager);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.SetThresholdEncryptionKey(thresholdEncKey, manager);
        keyManagerProxy.setThresholdEncryptionKey(thresholdEncKey);
        assertEq(keyManagerProxy.thresholdEncryptionKey(), thresholdEncKey);
    }

    function test_setNextCommittee() public {
        KeyManager.CommitteeMember[] memory committeeMembers = new KeyManager.CommitteeMember[](1);

        bytes memory randomBytes = abi.encodePacked("1");
        committeeMembers[0] = KeyManager.CommitteeMember({
            pubKey: randomBytes,
            secureChannelKey: randomBytes,
            dkgEncKey: randomBytes,
            networkAddress: "0x0000000000000000000000000000000000000000"
        });

        vm.prank(manager);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.ScheduledCommittee(
            0, uint64(block.timestamp), uint64(committeeMembers.length), keccak256(abi.encode(committeeMembers)), manager
        );
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), committeeMembers);

        // Test accessing the committee data
        (uint64 effectiveTimestamp, KeyManager.CommitteeMember[] memory retrievedMembers) =
            keyManagerProxy.getCommitteeById(0);
        assertEq(effectiveTimestamp, uint64(block.timestamp));
        assertEq(retrievedMembers.length, 1);
        assertEq(retrievedMembers[0].pubKey, committeeMembers[0].pubKey);
        assertEq(retrievedMembers[0].secureChannelKey, committeeMembers[0].secureChannelKey);
        assertEq(retrievedMembers[0].dkgEncKey, committeeMembers[0].dkgEncKey);
        assertEq(retrievedMembers[0].networkAddress, committeeMembers[0].networkAddress);

        // Test accessing the current committee
        uint64 currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 0);
        (effectiveTimestamp, retrievedMembers) = keyManagerProxy.getCommitteeById(currentCommitteeId);
        assertEq(effectiveTimestamp, uint64(block.timestamp));
        assertEq(retrievedMembers.length, 1);
        assertEq(retrievedMembers[0].pubKey, committeeMembers[0].pubKey);
        assertEq(retrievedMembers[0].secureChannelKey, committeeMembers[0].secureChannelKey);
    }

    function test_setManager() public {
        address newManager = makeAddr("newManager");
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.ChangedManager(manager, newManager, owner);
        keyManagerProxy.setManager(newManager);
        assertEq(keyManagerProxy.manager(), newManager);
    }

    function test_revertWhenInvalidAddress_setManager() public {
        vm.startPrank(owner);
        // revert for the zero address
        vm.expectRevert(abi.encodeWithSelector(KeyManager.InvalidAddress.selector, address(0)));
        keyManagerProxy.setManager(address(0));

        // revert for the same manager
        vm.expectRevert(abi.encodeWithSelector(KeyManager.InvalidAddress.selector, manager));
        keyManagerProxy.setManager(manager);
        vm.stopPrank();
    }

    function test_revertWhenNotOwner_setManager() public {
        vm.startPrank(manager);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, manager));
        keyManagerProxy.setManager(manager);
        vm.stopPrank();
    }

    function test_revertWhenNotManager_setThresholdEncryptionKey() public {
        bytes memory thresholdEncKey = abi.encodePacked("1");
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NotManager.selector, address(this)));
        keyManagerProxy.setThresholdEncryptionKey(thresholdEncKey);
    }

    function test_revertWhenThresholdEncryptionKeyAlreadySet_setThresholdEncryptionKey() public {
        bytes memory thresholdEncKey = abi.encodePacked("1");
        vm.startPrank(manager);
        keyManagerProxy.setThresholdEncryptionKey(thresholdEncKey);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.ThresholdEncryptionKeyAlreadySet.selector));
        keyManagerProxy.setThresholdEncryptionKey(thresholdEncKey);
        vm.stopPrank();
    }

    function test_revertWhenNotManager_setNextCommittee() public {
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NotManager.selector, address(this)));
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), new KeyManager.CommitteeMember[](0));

        // the owner should not be able to schedule the committee as it's not the manager
        // the owner can become the manager by calling setManager
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NotManager.selector, owner));
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), new KeyManager.CommitteeMember[](0));
    }

   

    // Tests for currentCommitteeId function
    function test_revertWhenNoCommitteeScheduled_emptyCommittees() public {
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NoCommitteees.selector));
        keyManagerProxy.currentCommitteeId();
    }

    function test_currentCommitteeId_oneCommitteeScheduled_effectiveNow() public {
        // Create a committee that's effective now
        KeyManager.CommitteeMember[] memory committeeMembers = new KeyManager.CommitteeMember[](1);
        bytes memory randomBytes = abi.encodePacked("1");
        committeeMembers[0] = KeyManager.CommitteeMember({
            pubKey: randomBytes,
            secureChannelKey: randomBytes,
            dkgEncKey: randomBytes,
            networkAddress: "0x0000000000000000000000000000000000000000"
        });

        uint64 effectiveTimestamp = uint64(block.timestamp);
        vm.prank(manager);
        keyManagerProxy.setNextCommittee(effectiveTimestamp, committeeMembers);

        uint64 currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 0);
    }

    function test_revertWhenNoCommitteeScheduled_currentCommitteeId() public {
        // Create a committee that's effective in the future
        KeyManager.CommitteeMember[] memory committeeMembers = new KeyManager.CommitteeMember[](1);
        bytes memory randomBytes = abi.encodePacked("1");
        committeeMembers[0] = KeyManager.CommitteeMember({
            pubKey: randomBytes,
            secureChannelKey: randomBytes,
            dkgEncKey: randomBytes,
            networkAddress: "0x0000000000000000000000000000000000000000"
        });

        uint64 effectiveTimestamp = uint64(block.timestamp + 100);
        vm.prank(manager);
        keyManagerProxy.setNextCommittee(effectiveTimestamp, committeeMembers);

        vm.expectRevert(
            abi.encodeWithSelector(
                KeyManager.NoCommitteeScheduled.selector, effectiveTimestamp
            )
        );
        keyManagerProxy.currentCommitteeId();
    }

    function test_currentCommitteeId_singleCommittee_effectiveInThePast() public {
        // Create a committee that was effective in the past
        KeyManager.CommitteeMember[] memory committeeMembers = new KeyManager.CommitteeMember[](1);
        bytes memory randomBytes = abi.encodePacked("1");
        committeeMembers[0] = KeyManager.CommitteeMember({
            pubKey: randomBytes,
            secureChannelKey: randomBytes,
            dkgEncKey: randomBytes,
            networkAddress: "0x0000000000000000000000000000000000000000"
        });

        uint64 effectiveTimestamp = 100;
        vm.prank(manager);
        keyManagerProxy.setNextCommittee(effectiveTimestamp, committeeMembers);

        vm.warp(101);
        uint64 currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 0);
    }

    function test_currentCommitteeId_multipleCommittees() public {
        // Create multiple committees with different timestamps
        KeyManager.CommitteeMember[] memory committeeMembers = new KeyManager.CommitteeMember[](1);
        bytes memory randomBytes = abi.encodePacked("1");
        committeeMembers[0] = KeyManager.CommitteeMember({
            pubKey: randomBytes,
            secureChannelKey: randomBytes,
            dkgEncKey: randomBytes,
            networkAddress: "0x0000000000000000000000000000000000000000"
        });

        vm.startPrank(manager);

        // Committee 0: effective now
        uint64 timestamp0 = uint64(block.timestamp);
        keyManagerProxy.setNextCommittee(timestamp0, committeeMembers);

        // Committee 1: effective in 100 seconds
        uint64 timestamp1 = uint64(block.timestamp + 100);
        keyManagerProxy.setNextCommittee(timestamp1, committeeMembers);

        // Committee 2: effective in 200 seconds
        uint64 timestamp2 = uint64(block.timestamp + 200);
        keyManagerProxy.setNextCommittee(timestamp2, committeeMembers);

        vm.stopPrank();

        // Test current committee (should be committee 0)
        uint64 currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 0);

        // Test at timestamp1 - only warp once to minimize gas
        vm.warp(timestamp1);
        currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 1);

        // Test at timestamp2 - only warp once more
        vm.warp(timestamp2);
        currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 2);
    }

    function test_nextCommitteeId() public {
        KeyManager.CommitteeMember[] memory committeeMembers = new KeyManager.CommitteeMember[](1);
        bytes memory randomBytes = abi.encodePacked("1");
        committeeMembers[0] = KeyManager.CommitteeMember({
            pubKey: randomBytes,
            secureChannelKey: randomBytes,
            dkgEncKey: randomBytes,
            networkAddress: "0x0000000000000000000000000000000000000000"
        });

        vm.startPrank(manager);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), committeeMembers);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp+100), committeeMembers);
        vm.stopPrank();

        uint64 nextCommitteeId = keyManagerProxy.nextCommitteeId();
        assertEq(nextCommitteeId, 1);
    }

    function test_revertWhenNoNextCommittee_nextCommitteeId() public {
        test_nextCommitteeId();
        (uint64 lastEffectiveTimestamp,) = keyManagerProxy.getCommitteeById(0);
        vm.warp(uint64(block.timestamp + 100));
        (uint64 nextEffectiveTimestamp,) = keyManagerProxy.getCommitteeById(keyManagerProxy.currentCommitteeId());
        assertNotEq(nextEffectiveTimestamp, lastEffectiveTimestamp);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NoCommitteeScheduled.selector, nextEffectiveTimestamp));
        keyManagerProxy.nextCommitteeId();

        vm.warp(uint64(block.timestamp + 200));
        // confirm that the next effective timestamp is the same as the last effective timestamp
        (uint64 nextEffectiveTimestamp2,) = keyManagerProxy.getCommitteeById(keyManagerProxy.currentCommitteeId());
        assertEq(nextEffectiveTimestamp2, nextEffectiveTimestamp);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NoCommitteeScheduled.selector, nextEffectiveTimestamp2));
        keyManagerProxy.nextCommitteeId();
    }       
}
