import { LiabilityTree } from './LiabilityTree';

import { AccountUpdate, MerkleTree, Mina, PrivateKey, isReady, shutdown } from "o1js";

describe('LiabilityTree.js', () => {
  let treePrivateKey : PrivateKey,
    incTree: LiabilityTree,
    refTree: MerkleTree,
    feePayer: PrivateKey;

  beforeAll(async () => {
    await isReady;

    await LiabilityTree.compile()

    let Local = Mina.LocalBlockchain();
    Mina.setActiveInstance(Local);

    feePayer = Local.testAccounts[0].privateKey;

    treePrivateKey = PrivateKey.random();
    incTree = new LiabilityTree(treePrivateKey.toPublicKey());

    let txn = await Mina.transaction(feePayer, () => {
      AccountUpdate.fundNewAccount(feePayer.toPublicKey());
      incTree.deploy({ zkappKey: treePrivateKey });
    });
    await txn.sign([feePayer, treePrivateKey]).send();
  });

  afterAll(async () => {
    setTimeout(shutdown, 0);
  });

  describe('LiabilityTree()', () => {
    it.todo('should be correct');
  });
});
