import { Deposit, LiabilityTree, LiabilityProof, LiabilityLeaf, LiabilityWitness, users } from './LiabilityTree';

import { AccountUpdate, Field, MerkleTree, Mina, PrivateKey, Signature, isReady, shutdown } from "o1js";

describe('LiabilityTree.js', () => {
  let treePrivateKey : PrivateKey,
    incTree: LiabilityTree,
    refTree: MerkleTree,
    feePayer: PrivateKey,
    exchange: PrivateKey;


  beforeAll(async () => {
    await isReady;

    await LiabilityTree.compile()

    exchange = users['exchange'];
    let Local = Mina.LocalBlockchain();
    Mina.setActiveInstance(Local);

    feePayer = Local.testAccounts[0].privateKey;

    treePrivateKey = PrivateKey.random();
    incTree = new LiabilityTree(treePrivateKey.toPublicKey());
    refTree = new MerkleTree(32);

    let txn = await Mina.transaction(feePayer, () => {
      AccountUpdate.fundNewAccount(feePayer.toPublicKey());
      incTree.deploy({ zkappKey: treePrivateKey });
    });
    await txn.sign([feePayer, treePrivateKey]).send();
  });

  afterAll(async () => {
    setTimeout(shutdown, 0);
  });

  describe('Deposit overflow', () => {
    it.todo('todo');
  });

  describe('Withdraw underflow', () => {
    it.todo('todo');
  });


  it('Deposit', async () => {
    let key = PrivateKey.random();
    let index = BigInt(Math.floor(Math.random() * 2 ** 31));

    let deposit = new Deposit({account: key.toPublicKey(), amount: Field(100), tid: Field(0), prev: Field(0)});
    let hash = deposit.hash();
    let sig = Signature.create(key, deposit.toFields())
    let leaf = new LiabilityLeaf({account: key.toPublicKey(), balance: Field(0), prev: Field(0)});
    let witness = new LiabilityWitness(refTree.getWitness(index))
    let proof = new LiabilityProof({leaf: leaf, witness: witness});

    let txn = await Mina.transaction(feePayer, () => {
      incTree.deposit(exchange, deposit, sig, proof);
    });

    await txn.prove()
    await txn.sign([key]).send();

    let nextLeaf = new LiabilityLeaf({account: key.toPublicKey(), balance: deposit.amount, prev: Field(0)});
    refTree.setLeaf(index, nextLeaf.hash())

    expect(incTree.root.get()).toEqual(refTree.getRoot());
  });

  it('Deposit fails without valid signature', async () => {
    let key = PrivateKey.random();
    let index = BigInt(Math.floor(Math.random() * 2 ** 31));

    let deposit = new Deposit({account: key.toPublicKey(), amount: Field(100), tid: Field(0), prev: Field(0)});
    let hash = deposit.hash();
    let sig = Signature.create(exchange, deposit.toFields())
    let leaf = new LiabilityLeaf({account: key.toPublicKey(), balance: Field(0), prev: Field(0)});
    let witness = new LiabilityWitness(refTree.getWitness(index))
    let proof = new LiabilityProof({leaf: leaf, witness: witness});

    let txn = await Mina.transaction(feePayer, () => {
      incTree.deposit(exchange, deposit, sig, proof);
    });

    await txn.prove();
    await txn.sign([key]).send();

    let nextLeaf = new LiabilityLeaf({account: key.toPublicKey(), balance: deposit.amount, prev: Field(0)});
    refTree.setLeaf(index, nextLeaf.hash())

    expect(incTree.root.get()).toEqual(refTree.getRoot());
  });
});
