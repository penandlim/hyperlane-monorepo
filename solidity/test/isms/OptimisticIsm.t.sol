// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {IOptimisticIsm} from "../../contracts/interfaces/isms/IOptimisticIsm.sol";
import {StaticOptimisticIsm} from "../../contracts/isms/optimistic/StaticOptimisticIsm.sol";
import {StaticOptimisticIsmFactory} from "../../contracts/isms/optimistic/StaticOptimisticIsmFactory.sol";
import {TestIsm, MOfNTestUtils} from "./IsmTestUtils.sol";

contract OptimisticIsmTest is Test {
    uint256 constant FRAUD_WINDOW = 7 days;
    StaticOptimisticIsmFactory factory;
    StaticOptimisticIsm ism;
    address submodule;
    bytes metadata;

    function setUp() public {
        factory = new StaticOptimisticIsmFactory();
    }

    function deployOptimisticIsmWithWatchers(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) internal returns (address[] memory) {
        bytes32 randomness = seed;
        address[] memory watchers = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            randomness = keccak256(abi.encode(randomness));
            address randomAddress = address(uint160(uint256(randomness)));
            watchers[i] = address(randomAddress);
        }
        ism = StaticOptimisticIsm(factory.deploy(watchers, m));
        randomness = keccak256(abi.encode(randomness));
        metadata = abi.encode(randomness);
        submodule = address(new TestIsm(metadata));
        return watchers;
    }

    function testInitialize_owner(
        uint8 m,
        uint8 n,
        bytes32 seed,
        address owner
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(owner, submodule, FRAUD_WINDOW);

        assertTrue(ism.owner() == owner);
    }

    function testInitialize_submodule(
        uint8 m,
        uint8 n,
        bytes32 seed,
        address _subModule,
        bytes memory message
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(_subModule != address(0));
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), _subModule, FRAUD_WINDOW);

        assertTrue(address(ism.submodule(message)) == _subModule);
    }

    function testInitialize_revertsWithZerosubmodule(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        vm.expectRevert(bytes("address(0)"));
        ism.initialize(address(this), address(0), FRAUD_WINDOW);
    }

    function testInitialize_revertsWithOutOfBoundsFraudWindow(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        vm.assume(
            fraudWindow < ism.MIN_FRAUD_WINDOW() ||
                fraudWindow > ism.MAX_FRAUD_WINDOW()
        );

        vm.expectRevert(bytes("fraudOutOfBounds"));
        ism.initialize(address(this), submodule, fraudWindow);
    }

    function testWatchersAndThreshold(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        address[] memory expectedWatchers = deployOptimisticIsmWithWatchers(
            m,
            n,
            seed
        );
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        (address[] memory actualWatchers, uint8 actualThreshold) = ism
            .watchersAndThreshold("");
        assertEq(abi.encode(actualWatchers), abi.encode(expectedWatchers));
        assertEq(actualThreshold, m);
    }

    function testSetSubmodule(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        address newSubmodule = address(new TestIsm(""));
        ism.setSubmodule(newSubmodule);
        assertTrue(address(ism.submodule("")) == newSubmodule);
    }

    function testSetSubmodule_revertsWhenNonOwner(
        uint8 m,
        uint8 n,
        bytes32 seed,
        address nonOwner
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(nonOwner != address(this));
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        address newSubmodule = address(new TestIsm(""));
        vm.prank(nonOwner);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        ism.setSubmodule(newSubmodule);
    }

    function testSetSubnmodule_revertsWithZeroAddress(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        vm.expectRevert(bytes("address(0)"));
        ism.setSubmodule(address(0));
    }

    function testIsWatcher(
        uint8 m,
        uint8 n,
        bytes32 seed,
        address nonWatcher,
        bytes memory message
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        address[] memory watchers = deployOptimisticIsmWithWatchers(m, n, seed);
        for (uint256 i = 0; i < n; i++) {
            vm.assume(watchers[i] != nonWatcher);
        }
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        for (uint256 i = 0; i < n; i++) {
            assertTrue(ism.isWatcher(watchers[i]));
            assertTrue(ism.isWatcher(message, watchers[i]));
        }
        assertTrue(!ism.isWatcher(nonWatcher));
        assertTrue(!ism.isWatcher(message, nonWatcher));
    }

    function testMarkFraudulent(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        address[] memory watchers = deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        // call markFraudulent for m watchers
        for (uint256 i = 0; i < m; i++) {
            vm.prank(watchers[i]);
            ism.markFraudulent(submodule);
            assertTrue(ism.fraudulentCounter(submodule) == i + 1);
        }
        assertTrue(ism.fraudulentCounter(submodule) == m);
    }

    function testMarkFraudulent_revertsWhenCalledByNonWatchers(
        uint8 m,
        uint8 n,
        bytes32 seed,
        address nonWatcher
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        vm.assume(ism.isWatcher(nonWatcher) == false);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        vm.prank(nonWatcher);
        vm.expectRevert(bytes("!watcher"));
        ism.markFraudulent(submodule);
    }

    function testPreVerify(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        assertTrue(ism.preVerify(metadata, ""));
    }

    function testPreVerify_revertsWithDuplicateMessage(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        assertTrue(ism.preVerify(metadata, ""));
        vm.expectRevert(bytes("preVerified"));
        ism.preVerify(metadata, "");
    }

    function testPreVerify_revertsWithWrongMetadata(
        uint8 m,
        uint8 n,
        bytes32 seed,
        bytes calldata wrongMetadata
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(keccak256(wrongMetadata) != keccak256(metadata));
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        vm.expectRevert(bytes("!verify"));
        ism.preVerify(wrongMetadata, "");
    }

    function testVerify_revertsWithoutPreVerify(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        vm.expectRevert(bytes("!isPreVerified"));
        ism.verify(metadata, "");
    }

    function testVerify_revertsBeforeFraudWindowCloses(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint256 waitDuration
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(waitDuration <= FRAUD_WINDOW);
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        ism.preVerify(metadata, "");
        // skip the fraud window timestamp
        vm.warp(block.timestamp + waitDuration);
        vm.expectRevert(bytes("!fraudWindow"));
        ism.verify(metadata, "");
    }

    function testVerify_revertsIfSubmoduleIsFraudulent(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        address[] memory watchers = deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        ism.preVerify(metadata, "");
        // call markFraudulent for m watchers
        for (uint256 i = 0; i < m; i++) {
            vm.prank(watchers[i]);
            ism.markFraudulent(submodule);
        }
        vm.warp(block.timestamp + FRAUD_WINDOW + 1);
        vm.expectRevert(bytes("!fraudThreshold"));
        ism.verify(metadata, "");
    }

    function testVerify(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        address[] memory watchers = deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        ism.preVerify(metadata, "");
        // call markFraudulent for m - 1 watchers
        for (uint256 i = 0; i < m - 1; i++) {
            vm.prank(watchers[i]);
            ism.markFraudulent(submodule);
        }
        vm.warp(block.timestamp + FRAUD_WINDOW + 1);
        assertTrue(ism.verify(metadata, ""));
    }

    function testVerify_passesWithEmptyMetadata(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);
        ism.initialize(address(this), submodule, FRAUD_WINDOW);

        ism.preVerify(metadata, "");
        vm.warp(block.timestamp + FRAUD_WINDOW + 1);
        assertTrue(ism.verify("", ""));
    }
}
