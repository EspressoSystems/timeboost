// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract KeyManager is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    struct CommitteeMember {
        bytes pubKey;
        bytes secureChannelKey;
        bytes dkgEncKey;
        string networkAddress;
    }

    struct Committee {
        uint64 effectiveTimestamp;
        uint64 id;
        CommitteeMember[] committeeMembers;
    }

    event ScheduledCommittee(uint64 indexed id, uint64 effectiveTimestamp, uint64 membersCount, bytes32 membersHash, address indexed scheduledBy);
    event SetThresholdEncryptionKey(bytes thresholdEncryptionKey, address indexed setBy);
    event ChangedManager(address indexed oldManager, address indexed newManager, address indexed changedBy);

    error NotManager(address caller);
    error InvalidAddress(address);
    error ThresholdEncryptionKeyAlreadySet();
    error CommitteeIdDoesNotExist(uint64 committeeId, uint64 committeesLength);
    error InvalidCommitteeMembers();
    error InvalidEffectiveTimestamp(uint64 effectiveTimestamp, uint64 lastEffectiveTimestamp);
    error NoCommitteeScheduled(uint64 lastEffectiveTimestamp);
    error CommitteeIdOverflow();
    error NoCommitteees();

    bytes public thresholdEncryptionKey;
    Committee[] public committees;
    address public manager;
    uint256[49] private __gap;

    modifier onlyManager() {
        _onlyManager();
        _;
    }

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
            revert InvalidAddress(initialManager);
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
    function setManager(address newManager) external onlyOwner {
        if (newManager == address(0) || newManager == manager) {
            revert InvalidAddress(newManager);
        }
        address oldManager = manager;
        manager = newManager;
        emit ChangedManager(oldManager, newManager, msg.sender);
    }

    /**
     * @notice This function is used to set the threshold encryption key.
     * @dev Reverts if the threshold encryption key is already set.
     * @dev Reverts if the caller is not the manager.
     * @dev Assumes that the threshold encryption key is valid.
     * @param newThresholdEncryptionKey The threshold encryption key.
     */
    function setThresholdEncryptionKey(bytes calldata newThresholdEncryptionKey) external onlyManager {
        if (thresholdEncryptionKey.length > 0) {
            revert ThresholdEncryptionKeyAlreadySet();
        }
        thresholdEncryptionKey = newThresholdEncryptionKey;
        emit SetThresholdEncryptionKey(thresholdEncryptionKey, msg.sender);
    }

    /**
     * @notice This function is used to set the next committee.
     * @dev Reverts if the members array is empty.
     * @dev Reverts if the effective timestamp is less than the last effective timestamp.
     * @dev Reverts if the committees array is at uint64.max.
     * @dev Assumes that committee members are not deleted from the committee array.
     * @dev Assumes that the committee members are valid.
     * @param effectiveTimestamp The effective timestamp of the committee.
     * @param members The committee members.
     * @return committeeId The id of the new committee.
     */
    function setNextCommittee(uint64 effectiveTimestamp, CommitteeMember[] calldata members)
        external
        onlyManager
        returns (uint64 committeeId)
    {
        if (members.length == 0) {
            revert InvalidCommitteeMembers();
        }

        // ensure the effective timestamp is greater than the last effective timestamp
        if (committees.length > 0) {
            uint64 lastTimestamp = committees[committees.length - 1].effectiveTimestamp;
            if (effectiveTimestamp <= lastTimestamp) {
                revert InvalidEffectiveTimestamp(effectiveTimestamp, lastTimestamp);
            }
        }

        if (committees.length > type(uint64).max) revert CommitteeIdOverflow();

        committeeId = uint64(committees.length);
        Committee storage newCommittee = committees.push();
        newCommittee.effectiveTimestamp = effectiveTimestamp;
        newCommittee.id = committeeId;
        newCommittee.committeeMembers = members;

        emit ScheduledCommittee(committeeId, effectiveTimestamp, uint64(members.length), keccak256(abi.encode(members)), msg.sender);
        return committeeId;
    }

    /**
     * @notice This function is used to get the committee by id.
     * @dev Reverts if the id is greater than the length of the committees array.
     * @dev Reverts if the committees array is empty.
     * @dev Assumes that committees are not deleted from the committee array.
     * @param id The id of the committee.
     * @return effectiveTimestamp The effective timestamp of the committee.
     * @return committeeMembers The committee members.
     */
    function getCommitteeById(uint64 id)
        external
        view
        returns (uint64 effectiveTimestamp, CommitteeMember[] memory committeeMembers)
    {
        if (committees.length == 0) {
            revert NoCommitteees();
        }
        if (id >= committees.length) {
            revert CommitteeIdDoesNotExist(id, uint64(committees.length));
        }
        return (committees[id].effectiveTimestamp, committees[id].committeeMembers);
    }

    /**
     * @notice This function is used to get the current committee id.
     * @dev Reverts if the committees array is empty.
     * @dev Reverts if there is no committee scheduled.
     * @dev Assumes that committees are stored in ascending order of effective timestamp.
     * @dev Assumes that committees are not deleted from the committee array.
     * @return committeeId The current committee id.
     */
    function currentCommitteeId() public view returns (uint64 committeeId) {
        if (committees.length == 0) {
            revert NoCommitteees();
        }

        uint64 currentTimestamp = uint64(block.timestamp);
        if (currentTimestamp < committees[0].effectiveTimestamp) {
            revert NoCommitteeScheduled(committees[0].effectiveTimestamp);
        }
        if (currentTimestamp >= committees[committees.length - 1].effectiveTimestamp) {
            return committees[committees.length - 1].id;
        }

        uint256 lo = 0;
        uint256 hi = committees.length - 1;
        while (lo < hi) {
            uint256 mid = (lo + hi + 1) / 2;
            if (committees[mid].effectiveTimestamp <= currentTimestamp) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        return committees[lo].id;
    }

    /**
     * @notice This function is used to get the next committee id.
     * @dev Reverts if there is no next committee.
     * @dev Assumes that committees are stored in ascending order of effective timestamp.
     * @dev Assumes that committees are not deleted from the committee array.
     * @return committeeId The next committee id.
     */
    function nextCommitteeId() public view returns (uint64 committeeId) {
        uint64 currCommitteeId = currentCommitteeId();
        if (currCommitteeId == committees.length - 1) {
            revert NoCommitteeScheduled(committees[currCommitteeId].effectiveTimestamp);
        }
        return currCommitteeId + 1;
    }
}
