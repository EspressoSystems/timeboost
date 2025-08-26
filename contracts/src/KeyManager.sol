// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract KeyManager is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    struct CommitteeMember {
        /// @notice public key for consensus votes, also used as the primary label for a node
        bytes sigKey;
        /// @notice DH public key used for authenticated network messages
        bytes dhKey;
        /// @notice public key for encrypting DKG-specific payloads
        bytes dkgKey;
        /// @notice a network address: `ip:port` or `hostname:port`
        string networkAddress;
    }

    /// @notice The consensus committee rotates with each epoch, registered by contract `manager`.
    /// @notice Timeboost makes the simplifying decision that this committee is exactly the keyset
    struct Committee {
        /// @notice unique identifier for the committee, assigned by this contract
        uint64 id;
        /// @notice wall clock time since unix epoch for this committee to be active
        uint64 effectiveTimestamp;
        /// @notice constituting members and their key materials
        CommitteeMember[] members;
    }

    /// @notice Emitted when a committee is created.
    /// @param id The id of the committee.
    event CommitteeCreated(uint64 indexed id);

    /// @notice Emitted when the threshold encryption key is set.
    /// @param thresholdEncryptionKey The threshold encryption key.
    event ThresholdEncryptionKeyUpdated(bytes thresholdEncryptionKey);

    /// @notice Emitted when the manager is changed.
    /// @param oldManager The old manager.
    /// @param newManager The new manager.
    event ManagerChanged(address indexed oldManager, address indexed newManager);

    /// @notice Emitted when a committee is removed.
    /// @param fromId The id of the first committee to prune.
    /// @param toId The id of the last committee to prune.
    event CommitteesPruned(uint64 indexed fromId, uint64 indexed toId);

    /// @notice Thrown when the caller is not the manager.
    /// @param caller The address that called the function.
    error NotManager(address caller);

    /// @notice Thrown when the address is invalid.
    error InvalidAddress();

    /// @notice Thrown when the threshold encryption key is already set.
    error ThresholdEncryptionKeyAlreadySet();

    /// @notice Thrown when the committee id does not exist.
    /// @param committeeId The id of the committee.
    error CommitteeIdDoesNotExist(uint64 committeeId);
    /// @notice Thrown when the committee is empty.
    error EmptyCommitteeMembers();
    /// @notice Thrown when the effective timestamp is invalid.
    error InvalidEffectiveTimestamp(uint64 effectiveTimestamp, uint64 lastEffectiveTimestamp);
    /// @notice Thrown when there is no committee scheduled.
    error NoCommitteeScheduled();
    /// @notice Thrown when the committee id overflows.
    error CommitteeIdOverflow();
    /// @notice Thrown when the committee is too recent to remove.
    error CannotRemoveRecentCommittees();
    /// @notice Thrown when pruning with invalid range.
    error InvalidPruneRange(uint64 upToCommitteeId, uint64 oldestStored, uint64 nextCommitteeId);

    /// @notice The threshold encryption key for the committee.
    bytes public thresholdEncryptionKey;
    /// @notice The mapping of committee ids to committees.
    mapping(uint64 => Committee) public committees;
    /// @notice The manager of the contract.
    address public manager;
    /// @notice The next committee id.
    uint64 public nextCommitteeId;
    /// @notice The oldest committee id still stored in the mapping
    uint64 private _oldestStoredCommitteeId;
    /// @notice The gap for future upgrades.
    uint256[48] private __gap;

    /// @notice Modifier to check if the caller is the manager.
    modifier onlyManager() {
        _onlyManager();
        _;
    }

    /// @notice Internal function to check if the caller is the manager.
    function _onlyManager() internal view {
        if (msg.sender != manager) {
            revert NotManager(msg.sender);
        }
    }

    constructor() {
        _disableInitializers();
    }

    /**
     * @notice This function is used to initialize the contract.
     * @dev Reverts if the manager is the zero address.
     * @dev Assumes that the manager is valid.
     * @dev This must be called once when the contract is first deployed.
     * @param initialManager The initial manager.
     */
    function initialize(address initialManager) external initializer {
        if (initialManager == address(0)) {
            revert InvalidAddress();
        }
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        manager = initialManager;
    }

    /**
     * @notice This function is used to authorize the upgrade of the contract.
     * @dev Reverts if the caller is not the owner.
     * @dev Assumes that the new implementation is valid.
     * @param newImplementation The new implementation.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @notice This function is used to set the manager.
     * @dev Reverts if the manager is the zero address or the same as the current manager.
     * @dev Reverts if the caller is not the owner.
     * @dev Assumes that the manager is valid.
     * @param newManager The new manager.
     */
    function setManager(address newManager) external virtual onlyOwner {
        if (newManager == address(0) || newManager == manager) {
            revert InvalidAddress();
        }
        address oldManager = manager;
        manager = newManager;
        emit ManagerChanged(oldManager, newManager);
    }

    /**
     * @notice This function is used to set the threshold encryption key.
     * @dev Reverts if the threshold encryption key is already set.
     * @dev Reverts if the caller is not the manager.
     * @dev Assumes that the threshold encryption key is valid.
     * @param newThresholdEncryptionKey The threshold encryption key.
     */
    function setThresholdEncryptionKey(bytes calldata newThresholdEncryptionKey) external virtual onlyManager {
        if (thresholdEncryptionKey.length > 0) {
            revert ThresholdEncryptionKeyAlreadySet();
        }
        thresholdEncryptionKey = newThresholdEncryptionKey;
        emit ThresholdEncryptionKeyUpdated(newThresholdEncryptionKey);
    }

    /**
     * @notice This function is used to set the next committee.
     * @dev Reverts if the members array is empty.
     * @dev Reverts if the effective timestamp is less than the last effective timestamp.
     * @dev Reverts if the committees mapping is at uint64.max.
     * @dev Assumes that the committee members are valid.
     * @param effectiveTimestamp The effective timestamp of the committee.
     * @param members The committee members.
     * @return committeeId The id of the new committee.
     */
    function setNextCommittee(uint64 effectiveTimestamp, CommitteeMember[] calldata members)
        external
        virtual
        onlyManager
        returns (uint64 committeeId)
    {
        if (members.length == 0) {
            revert EmptyCommitteeMembers();
        }

        // ensure the effective timestamp is greater than the last effective timestamp
        if (nextCommitteeId > 0) {
            uint64 lastTimestamp = committees[nextCommitteeId - 1].effectiveTimestamp;
            if (effectiveTimestamp <= lastTimestamp) {
                revert InvalidEffectiveTimestamp(effectiveTimestamp, lastTimestamp);
            }
        }

        if (nextCommitteeId == type(uint64).max) revert CommitteeIdOverflow();

        committees[nextCommitteeId] =
            Committee({id: nextCommitteeId, effectiveTimestamp: effectiveTimestamp, members: members});

        nextCommitteeId++;

        emit CommitteeCreated(nextCommitteeId - 1);
        return nextCommitteeId - 1;
    }

    /**
     * @notice This function is used to get the committee by id.
     * @dev Reverts if the id is greater than the length of the committees mapping.
     * @dev Reverts if the id is less than the head committee id.
     * @param id The id of the committee.
     * @return committee The committee.
     */
    function getCommitteeById(uint64 id) external view virtual returns (Committee memory committee) {
        if (id < _oldestStoredCommitteeId || committees[id].id != id) {
            revert CommitteeIdDoesNotExist(id);
        }

        return committees[id];
    }

    /**
     * @notice This function is used to get the current committee id.
     * @dev Reverts if there is no committee scheduled at the current timestamp.
     * @dev Searches backwards through existing committees to find the active one.
     * @return committeeId The current committee id.
     */
    function currentCommitteeId() public view virtual returns (uint64 committeeId) {
        uint64 currentTimestamp = uint64(block.timestamp);

        if (nextCommitteeId == 0 || _oldestStoredCommitteeId >= nextCommitteeId) {
            revert NoCommitteeScheduled();
        }

        // Search backwards from most recent committee to oldest stored
        uint64 currCommitteeId = nextCommitteeId - 1;
        while (currCommitteeId >= _oldestStoredCommitteeId) {
            if (currentTimestamp >= committees[currCommitteeId].effectiveTimestamp) {
                return currCommitteeId;
            }

            if (currCommitteeId == 0) {
                break;
            }

            currCommitteeId--;
        }

        revert NoCommitteeScheduled();
    }

    /**
     * @notice Prunes all committees from _oldestStoredCommitteeId up to and including upToCommitteeId.
     * @dev This matches timeboost's garbage collection behavior of removing old committees in bulk.
     * @dev Reverts if upToCommitteeId is not in a valid range for pruning.
     * @dev Reverts if any committee in the range became effective within the last 10 minutes.
     * @param upToCommitteeId The highest committee ID to prune (inclusive).
     */
    function pruneUntil(uint64 upToCommitteeId) external virtual onlyManager {
        if (upToCommitteeId < _oldestStoredCommitteeId || upToCommitteeId >= nextCommitteeId) {
            revert InvalidPruneRange(upToCommitteeId, _oldestStoredCommitteeId, nextCommitteeId);
        }

        // Delete all committees in range
        uint64 cutOffTime = uint64(block.timestamp - 10 minutes);
        uint64 oldOldestStored = _oldestStoredCommitteeId;
        for (uint64 id = _oldestStoredCommitteeId; id <= upToCommitteeId; id++) {
            if (committees[id].effectiveTimestamp >= cutOffTime) {
                revert CannotRemoveRecentCommittees();
            }
            delete committees[id];
        }

        _oldestStoredCommitteeId = upToCommitteeId + 1;

        emit CommitteesPruned(oldOldestStored, upToCommitteeId);
    }
}
