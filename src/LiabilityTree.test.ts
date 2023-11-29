import { Deposit, LiabilityTree, LiabilityProof, LiabilityLeaf, LiabilityWitness, RollupProof, RollupProver, ReceiptProver, ReceiptProof } from './LiabilityTree';

import { AccountUpdate, Field, MerkleTree, Mina, PrivateKey, Signature, isReady, shutdown } from "o1js";
import { LiabilityState, randomDeposit, randomWithdraw } from './test/helpers';

describe('LiabilityTree.js', () => {
  let state : LiabilityState,
    feePayer: PrivateKey,
    keys: Array<PrivateKey>;

  beforeAll(async () => {
    await isReady;

    let Local = Mina.LocalBlockchain();
    Mina.setActiveInstance(Local);

    await ReceiptProver.compile();
    await RollupProver.compile();
    await LiabilityTree.compile();

    state = new LiabilityState();
    feePayer = Local.testAccounts[0].privateKey;
    keys = new Array<PrivateKey>();
    await state.addTree(Field(0), feePayer)
    
    for(let i = 0; i < 3; i++) {
      let key = PrivateKey.random();
      keys.push(key);
    }
  });

  afterAll(async () => {
    setTimeout(shutdown, 0);
  });

  it('Deposit', async () => {
    for(let i = 0; i < 10; i++) {
      let [deposit, sig] = await randomDeposit(feePayer, state, keys);
      await state.deposit(feePayer, deposit, sig);
    }
  });

  it('Withdraw', async () => {
    for(let i = 0; i < 5; i++) {
      let [deposit, sig] = await randomDeposit(feePayer, state, keys);
      await state.deposit(feePayer, deposit, sig);
    }

    for(let i = 0; i < 5; i++) {
      let [withdraw, sig] = await randomWithdraw(feePayer, state, keys);
      await state.withdraw(feePayer, withdraw, sig);
    }
  });

  it('Offline Deposit', async () => {
    //once get user state has an offline version, can remove this loop
    for(let i = 0; i < keys.length; i++) {
      await state.getUserState(feePayer, Field(0), keys[i].toPublicKey());
    }

    let receipts = new Array<ReceiptProof>();
    for(let i = 0; i < 5; i++) {
      let [deposit, sig] = await randomDeposit(feePayer, state, keys);
      const receipt = await state.offlineDeposit(feePayer, deposit, sig);
      receipts.push(receipt);
    }

    //once multiple liability trees are supported, aggregate each separately.
    const rollup = await state.rollup(Field(0), receipts);
    await state.finalize(feePayer, Field(0), rollup);
  });
});
