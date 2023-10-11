import { AccountUpdate, MerkleTree, Mina, PrivateKey, isReady, shutdown } from 'o1js';
import { AppendOnlyLiabilityTree } from './AppendOnlyLiabilityTree';

describe('AppendOnlyLiabilityTree.js', () => {
  let treePrivateKey : PrivateKey,
    incTree: AppendOnlyLiabilityTree,
    refTree: MerkleTree,
    feePayer: PrivateKey;

  beforeAll(async () => {
    await isReady;

    await AppendOnlyLiabilityTree.compile()

    let Local = Mina.LocalBlockchain();
    Mina.setActiveInstance(Local);

    feePayer = Local.testAccounts[0].privateKey;

    treePrivateKey = PrivateKey.random();
    incTree = new AppendOnlyLiabilityTree(treePrivateKey.toPublicKey());

    let txn = await Mina.transaction(feePayer, () => {
      AccountUpdate.fundNewAccount(feePayer.toPublicKey());
      incTree.deploy({ zkappKey: treePrivateKey });
    });
    await txn.sign([feePayer, treePrivateKey]).send();
  });
  afterAll(async () => {
    setTimeout(shutdown, 0);
  });

  describe('AppendOnlyLiabilityTree()', () => {
    it.todo('should be correct');
  });
});