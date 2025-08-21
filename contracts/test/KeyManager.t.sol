    // SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
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

    function createTestMembers() internal pure returns (KeyManager.CommitteeMember[] memory) {
        KeyManager.CommitteeMember[] memory members = new KeyManager.CommitteeMember[](1);
        bytes memory randomBytes = abi.encodePacked("1");
        members[0] = KeyManager.CommitteeMember({
            sigKey: randomBytes,
            dhKey: randomBytes,
            dkgKey: randomBytes,
            networkAddress: "127.0.0.1:8080"
        });
        return members;
    }

    function test_setThresholdEncryptionKey() public {
        bytes memory thresholdEncKey = abi.encodePacked("1");
        vm.prank(manager);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.ThresholdEncryptionKeyUpdated(thresholdEncKey);
        keyManagerProxy.setThresholdEncryptionKey(thresholdEncKey);
        assertEq(keyManagerProxy.thresholdEncryptionKey(), thresholdEncKey);
    }

    function test_setNextCommittee() public {
        KeyManager.CommitteeMember[] memory committeeMembers = createTestMembers();

        vm.prank(manager);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.CommitteeCreated(0);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), committeeMembers);

        // Test accessing the committee data
        KeyManager.Committee memory retrievedCommittee = keyManagerProxy.getCommitteeById(0);
        assertEq(retrievedCommittee.effectiveTimestamp, uint64(block.timestamp));
        assertEq(retrievedCommittee.members.length, 1);
        assertEq(retrievedCommittee.members[0].sigKey, committeeMembers[0].sigKey);
        assertEq(retrievedCommittee.members[0].dhKey, committeeMembers[0].dhKey);
        assertEq(retrievedCommittee.members[0].dkgKey, committeeMembers[0].dkgKey);
        assertEq(retrievedCommittee.members[0].networkAddress, committeeMembers[0].networkAddress);

        // Test accessing the current committee
        uint64 currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 0);
        retrievedCommittee = keyManagerProxy.getCommitteeById(currentCommitteeId);
        assertEq(retrievedCommittee.effectiveTimestamp, uint64(block.timestamp));
        assertEq(retrievedCommittee.members.length, 1);
        assertEq(retrievedCommittee.members[0].sigKey, committeeMembers[0].sigKey);
        assertEq(retrievedCommittee.members[0].dhKey, committeeMembers[0].dhKey);
        assertEq(retrievedCommittee.members[0].dkgKey, committeeMembers[0].dkgKey);
    }

    function test_revertWhenEmptyCommittee_setNextCommittee() public {
        vm.startPrank(manager);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.EmptyCommitteeMembers.selector));
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), new KeyManager.CommitteeMember[](0));
        vm.stopPrank();
    }

    function test_revertWhenInvalidEffectiveTimestamp_setNextCommittee() public {
        KeyManager.CommitteeMember[] memory members = createTestMembers();

        vm.startPrank(manager);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), members);

        // Try to create committee with earlier timestamp
        vm.expectRevert(
            abi.encodeWithSelector(
                KeyManager.InvalidEffectiveTimestamp.selector, uint64(block.timestamp - 1), uint64(block.timestamp)
            )
        );
        keyManagerProxy.setNextCommittee(uint64(block.timestamp - 1), members);
        vm.stopPrank();
    }

    function test_setManager() public {
        address newManager = makeAddr("newManager");
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.ManagerChanged(manager, newManager);
        keyManagerProxy.setManager(newManager);
        assertEq(keyManagerProxy.manager(), newManager);
    }

    function test_revertWhenInvalidAddress_setManager() public {
        vm.startPrank(owner);
        // revert for the zero address
        vm.expectRevert(abi.encodeWithSelector(KeyManager.InvalidAddress.selector));
        keyManagerProxy.setManager(address(0));

        // revert for the same manager
        vm.expectRevert(abi.encodeWithSelector(KeyManager.InvalidAddress.selector));
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
    function test_revertWhenEmptyCommittees_currentCommitteeId() public {
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NoCommitteeScheduled.selector));
        keyManagerProxy.currentCommitteeId();
    }

    function test_currentCommitteeId_oneCommitteeScheduled_effectiveNow() public {
        // Create a committee that's effective now
        KeyManager.CommitteeMember[] memory committeeMembers = createTestMembers();

        uint64 effectiveTimestamp = uint64(block.timestamp);
        vm.prank(manager);
        keyManagerProxy.setNextCommittee(effectiveTimestamp, committeeMembers);

        uint64 currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 0);
    }

    function test_revertWhenNoCommitteeScheduledAtCurrentTimestamp_currentCommitteeId() public {
        // Create a committee that's effective in the future
        KeyManager.CommitteeMember[] memory committeeMembers = createTestMembers();

        uint64 effectiveTimestamp = uint64(block.timestamp + 100);
        vm.prank(manager);
        keyManagerProxy.setNextCommittee(effectiveTimestamp, committeeMembers);

        vm.expectRevert(abi.encodeWithSelector(KeyManager.NoCommitteeScheduled.selector));
        keyManagerProxy.currentCommitteeId();
    }

    function test_currentCommitteeId_singleCommittee_effectiveInThePast() public {
        // Create a committee that was effective in the past
        KeyManager.CommitteeMember[] memory committeeMembers = createTestMembers();

        uint64 effectiveTimestamp = 100;
        vm.prank(manager);
        keyManagerProxy.setNextCommittee(effectiveTimestamp, committeeMembers);

        vm.warp(101);
        uint64 currentCommitteeId = keyManagerProxy.currentCommitteeId();
        assertEq(currentCommitteeId, 0);
    }

    function test_currentCommitteeId_multipleCommittees() public {
        // Create multiple committees with different timestamps
        KeyManager.CommitteeMember[] memory committeeMembers = createTestMembers();

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
        KeyManager.CommitteeMember[] memory committeeMembers = createTestMembers();

        vm.startPrank(manager);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), committeeMembers);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp + 100), committeeMembers);
        vm.stopPrank();

        uint64 nextCommitteeId = keyManagerProxy.nextCommitteeId();
        assertEq(nextCommitteeId, 2);
    }

    function test_pruneUntil() public {
        KeyManager.CommitteeMember[] memory members = createTestMembers();

        vm.startPrank(manager);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), members);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp + 10 minutes), members);

        vm.warp(uint64(block.timestamp + 20 minutes));

        // Remove first committee
        vm.expectEmit(true, true, true, true);
        emit KeyManager.CommitteesPruned(0, 0);
        keyManagerProxy.pruneUntil(0);

        // Verify first committee is deleted
        vm.expectRevert();
        keyManagerProxy.getCommitteeById(0);

        // Verify second committee still exists
        KeyManager.Committee memory committee1 = keyManagerProxy.getCommitteeById(1);
        assertEq(committee1.id, 1);
        vm.stopPrank();
    }

    function test_revertWhenCannotRemoveRecentCommittees_pruneUntil() public {
        KeyManager.CommitteeMember[] memory committeeMembers = createTestMembers();

        vm.startPrank(manager);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp), committeeMembers);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp + 10 minutes), committeeMembers);
        keyManagerProxy.setNextCommittee(uint64(block.timestamp + 20 minutes), committeeMembers);
        vm.warp(uint64(block.timestamp + 10 minutes));
        vm.expectRevert(abi.encodeWithSelector(KeyManager.CannotRemoveRecentCommittees.selector));
        keyManagerProxy.pruneUntil(0);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.CannotRemoveRecentCommittees.selector));
        keyManagerProxy.pruneUntil(1);
    }

    function test_revertWhenInvalidPruneRange_pruneUntil() public {
        vm.startPrank(manager);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.InvalidPruneRange.selector, 0, 0, 0));
        keyManagerProxy.pruneUntil(0);

        KeyManager.CommitteeMember[] memory committeeMembers = createTestMembers();

        keyManagerProxy.setNextCommittee(uint64(block.timestamp), committeeMembers);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.InvalidPruneRange.selector, 1, 0, 1));
        keyManagerProxy.pruneUntil(1);
        vm.stopPrank();
    }
}
