import {
  isReady,
  shutdown,
  Poseidon,
  Field,
  MerkleTree,
  MerkleWitness,
  PrivateKey,
  Mina,
  AccountUpdate,
  Provable
} from 'o1js';

import { IncrementalMerkleTree, IncrementalWitness, RollupProver } from './IncrementalMerkleTree';

/*
 * To get constraints:
 * IncrementalMerkleTree.analyzeMethods();
 */

describe('IncrementalMerkleTree.js', () => {
  let treePrivateKey : PrivateKey,
    incTree: IncrementalMerkleTree,
    refTree: MerkleTree,
    feePayer: PrivateKey;

  beforeAll(async () => {
    await isReady;

    await RollupProver.compile()
    await IncrementalMerkleTree.compile()

    let Local = Mina.LocalBlockchain();
    Mina.setActiveInstance(Local);

    feePayer = Local.testAccounts[0].privateKey;

    treePrivateKey = PrivateKey.random();
    incTree = new IncrementalMerkleTree(treePrivateKey.toPublicKey());

    let txn = await Mina.transaction(feePayer, () => {
      AccountUpdate.fundNewAccount(feePayer.toPublicKey());
      incTree.deploy({ zkappKey: treePrivateKey });
    });
    await txn.sign([feePayer, treePrivateKey]).send();
  });
  afterAll(async () => {
    setTimeout(shutdown, 0);
  });

  describe('IncrementalMerkleTree()', () => {
    it.todo('should be correct');
  });

  it('try some interactions', async () => {
    const tree = new MerkleTree(32);
    let leaves = [10, 200, 5/*, 6, 8, 21, 800, 329, 34, 375, 1234, 23, 64, 9, 768, 456, 345, 34, 234, 568, 43,35,4537,483,48,836,48,38,43,483,843,84*/].map(Field)

    console.log("length: " + tree.getWitness(0n).length)

    for(let i = 0; i < 32; i++) {
      console.log("level (" + i + "): " + tree.getNode(i, 0n).toBigInt())
    }

    for(let i = 0; i < leaves.length; i++) {
      let txn = await Mina.transaction(feePayer, () => {
        incTree.insert(leaves[i]);
      });
  
      await txn.prove()
      await txn.sign([treePrivateKey]).send();
    }

    /*let txn = await Mina.transaction(feePayer, () => {
      incTree.insert(leaves[0]);
    });

    await txn.prove()
    await txn.sign([treePrivateKey]).send();

    txn = await Mina.transaction(feePayer, () => {
      incTree.insert(leaves[1]);
    });

    await txn.prove()
    await txn.sign([treePrivateKey]).send();
    
    txn = await Mina.transaction(feePayer, () => {
      incTree.insert(leaves[2]);
    });

    await txn.prove()
    await txn.sign([treePrivateKey]).send();

    txn = await Mina.transaction(feePayer, () => {
      incTree.insert(leaves[3]);
    });

    await txn.prove()
    await txn.sign([treePrivateKey]).send();

    txn = await Mina.transaction(feePayer, () => {
      incTree.insert(leaves[4]);
    });

    await txn.prove()
    await txn.sign([treePrivateKey]).send();

    txn = await Mina.transaction(feePayer, () => {
      incTree.insert(leaves[5]);
    });

    await txn.prove()
    await txn.sign([treePrivateKey]).send();*/

    let txn = await Mina.transaction(feePayer, () => {
      incTree.sync(new IncrementalWitness(tree.getWitness(0n)));
    });

    await txn.prove()
    await txn.sign([treePrivateKey]).send();

    //tree.setLeaf(0n, leaves[0])
    tree.fill(leaves)

    console.log("Ref root: " + tree.getRoot());
    console.log("Inc Tree: " + incTree.root.get());

    expect(incTree.root.get()).toEqual(tree.getRoot());
    expect(incTree.ind.get().toBigInt()).toEqual(BigInt(leaves.length));
  });

  it('try some interactions', async () => {
  
  });
});
