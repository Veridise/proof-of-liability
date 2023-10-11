import { Escrow } from './Escrow';
import {
  isReady,
  shutdown,
  Poseidon,
  Field,
  MerkleTree,
  MerkleWitness,
  PrivateKey,
  Mina,
  AccountUpdate
} from 'o1js';

describe('Escrow.js', () => {
  let treePrivateKey : PrivateKey,
    incTree: Escrow,
    refTree: MerkleTree,
    feePayer: PrivateKey;

  beforeAll(async () => {
    await isReady;

    await Escrow.compile()

    let Local = Mina.LocalBlockchain();
    Mina.setActiveInstance(Local);

    feePayer = Local.testAccounts[0].privateKey;

    treePrivateKey = PrivateKey.random();
    incTree = new Escrow(treePrivateKey.toPublicKey());

    let txn = await Mina.transaction(feePayer, () => {
      AccountUpdate.fundNewAccount(feePayer.toPublicKey());
      incTree.deploy({ zkappKey: treePrivateKey });
    });
    await txn.sign([feePayer, treePrivateKey]).send();
  });

  afterAll(async () => {
    setTimeout(shutdown, 0);
  });

  describe('Escrow()', () => {
    it.todo('should be correct');
  });
});
