import { AccountUpdate, Field, MerkleTree, Mina, PrivateKey, PublicKey, Signature, UInt32, UInt64 } from 'o1js';
import { Deposit, LiabilityTree, HistoryWitness, LiabilityProof, LiabilityLeaf, LiabilityWitness, users, RollupProof, RollupProver, Withdraw, Swap, LIABILITY_HEIGHT, HISTORY_HEIGHT, zeros, ReceiptProver, ReceiptInput, TreeState, ReceiptProof } from '../LiabilityTree';

export class LiabilityState {
    tids: Array<Field>;
    tree: Map<BigInt, LiabilityTree>;
    ref: Map<BigInt, MerkleTree>;
    leaf: Map<BigInt, Map<string, LiabilityLeaf>>;
    treeIndex: Map<string, bigint>;
    histories: Map<BigInt, Map<string, MerkleTree>>;
    usedIds = new Set<bigint>();
    exchange: PrivateKey;
    totLiability: Map<BigInt, Field>;
    eid: Map<BigInt, Field>;

    constructor() {
        this.tids = new Array<Field>();
        this.tree = new Map<BigInt, LiabilityTree>();
        this.ref = new Map<BigInt, MerkleTree>();
        this.leaf = new Map<BigInt, Map<string, LiabilityLeaf>>();
        this.treeIndex = new Map<string, bigint>();
        this.usedIds = new Set<bigint>();
        this.exchange = users['exchange'];
        this.histories = new Map<BigInt, Map<string, MerkleTree>>();
        this.totLiability = new Map<BigInt, Field>();
        this.eid = new Map<BigInt, Field>();
    }

    tokens(): Array<Field> {
        return this.tids;
    }

    getTimestamp(): Field{
        return Field(Date.now())
    }

    getEid(id: Field): Field {
        const nextId = this.eid.get(id.toBigInt());
        if(nextId) {
            return nextId;
        }

        return Field(0);
    }

    async getUserState(feePayer: PrivateKey, tid: Field, key: PublicKey): Promise<LiabilityLeaf> {
        const treeLeaf = this.leaf.get(tid.toBigInt());
        if(!treeLeaf) {
            throw new Error("Tree Not Initialized");
        }
        const leaf = treeLeaf.get(key.toBase58());
        if(leaf) {
            return leaf;
        }

        const rTree = this.ref.get(tid.toBigInt());
        const lTree = this.tree.get(tid.toBigInt());
        if(!rTree || !lTree) {
            throw new Error("Undefined reference tree")
        }
        const eid = this.eid.get(tid.toBigInt());
        if(!eid) {
            throw new Error("Undefined reference tree")
        }
        const index = this.getUserIndex(key);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const newLeaf = new LiabilityLeaf({account: key, balance: Field(0), eid: eid, history: zeros[HISTORY_HEIGHT - 1], size: Field(0)})

        let txn = await Mina.transaction(feePayer, () => {
            lTree.create(this.exchange, new LiabilityProof({witness, leaf: newLeaf}))
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();

        rTree.setLeaf(index, newLeaf.hash());
        const history = new MerkleTree(HISTORY_HEIGHT);
        this.histories.get(tid.toBigInt())?.set(key.toBase58(), history);
        treeLeaf.set(key.toBase58(), newLeaf);

        console.log("create root: " + lTree.root.get());
        return newLeaf;
    }

    async getHistory(feePayer: PrivateKey, id: Field, key: PublicKey): Promise<MerkleTree> {
        let history = this.histories.get(id.toBigInt())?.get(key.toBase58());
        if(history) {
            return history;
        }

        const leaf = await this.getUserState(feePayer, id, key);
        history = this.histories.get(id.toBigInt())?.get(key.toBase58());
        if(history) {
            return history;
        }

        throw new Error("Undefined History")
    }

    async addTree(id: Field, feePayer: PrivateKey) {
        let privateKey = PrivateKey.random();
        let newTree = new LiabilityTree(privateKey.toPublicKey());
        let refTree = new MerkleTree(LIABILITY_HEIGHT);

        let txn = await Mina.transaction(feePayer, () => {
            AccountUpdate.fundNewAccount(feePayer.toPublicKey());
            newTree.deploy({ zkappKey: privateKey });
        });
        await txn.sign([feePayer, privateKey]).send();

        this.totLiability.set(id.toBigInt(), Field.from(0));
        this.tree.set(id.toBigInt(), newTree);
        this.ref.set(id.toBigInt(), refTree);
        this.leaf.set(id.toBigInt(), new Map<string, LiabilityLeaf>());
        this.histories.set(id.toBigInt(), new Map<string, MerkleTree>());
        this.eid.set(id.toBigInt(), Field(0));
        this.tids.push(id);
    }

    getUserIndex(key: PublicKey): bigint {
        let index = this.treeIndex.get(key.toBase58());
        if(index) {
            return index;
        }

        let id = BigInt(Math.round(Math.random() * (2 ** (LIABILITY_HEIGHT - 1))));
        while(this.usedIds.has(id)) {
            id = BigInt(Math.round(Math.random() * (2 ** (LIABILITY_HEIGHT - 1))));
        }
        this.usedIds.add(id);
        this.treeIndex.set(key.toBase58(), id);

        return id;
    }
    

    async deposit(feePayer: PrivateKey, req: Deposit, sig: Signature) {
        const lTree = this.tree.get(req.tid.toBigInt());
        const rTree = this.ref.get(req.tid.toBigInt());
        const history = await this.getHistory(feePayer, req.tid, req.account);
        const curTotal = this.totLiability.get(req.tid.toBigInt());

        if(!lTree || !rTree || !history || !curTotal) {
            throw new Error("Liability Tree Not Initialized");
        }

        const index = this.getUserIndex(req.account);
        const prevLeaf = await this.getUserState(feePayer, req.tid, req.account);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const historyWit = new HistoryWitness(history.getWitness(prevLeaf.size.toBigInt()));

        let txn = await Mina.transaction(feePayer, () => {
            lTree.deposit(this.exchange, req, sig, new LiabilityProof({leaf: prevLeaf, witness: witness}), historyWit);
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();
    
        history.setLeaf(prevLeaf.size.toBigInt(), req.prev)
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.add(req.amount), eid: req.eid, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash())
        this.totLiability.set(req.tid.toBigInt(), curTotal.add(req.amount));

        if(rTree.getRoot().toBigInt() != lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync");
        }

        console.log("root: " + lTree.root.get());

        this.leaf.get(req.tid.toBigInt())?.set(req.account.toBase58(), nextLeaf);
    }

    async offlineDeposit(feePayer: PrivateKey, req: Deposit, sig: Signature): Promise<ReceiptProof> {
        const lTree = this.tree.get(req.tid.toBigInt());
        const rTree = this.ref.get(req.tid.toBigInt());
        const history = await this.getHistory(feePayer, req.tid, req.account);
        const curTotal = this.totLiability.get(req.tid.toBigInt());

        if(!lTree || !rTree || !history || !curTotal) {
            throw new Error("Liability Tree Not Initialized");
        }

        const index = this.getUserIndex(req.account);
        const prevLeaf = await this.getUserState(feePayer, req.tid, req.account);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const historyWit = new HistoryWitness(history.getWitness(prevLeaf.size.toBigInt()));

        const state = new TreeState({root: rTree.getRoot(), totalLiability: curTotal});
        const inp = new ReceiptInput({state: state, witness: witness})
        const receipt = await ReceiptProver.deposit(inp, this.exchange, req, sig, prevLeaf, historyWit);
    
        history.setLeaf(prevLeaf.size.toBigInt(), prevLeaf.hash())
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.add(req.amount), eid: req.eid, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash());
        this.totLiability.set(req.tid.toBigInt(), curTotal.add(req.amount));

        this.leaf.get(req.tid.toBigInt())?.set(req.account.toBase58(), nextLeaf);
        console.log("rroot: " + rTree.getRoot());

        return receipt;
    }

    async rollup(tid: Field, receipts: Array<ReceiptProof>): Promise<RollupProof> {
        let worklist = new Array<RollupProof>();
        for(let i = 0; i < receipts.length; i += 2) {
            if(receipts.length - i >= 2) {
                const state = new TreeState({root: receipts[i].publicInput.state.root, totalLiability: receipts[i].publicInput.state.totalLiability});
                const rollup = await RollupProver.mergeReceipts(state, receipts[i], receipts[i + 1])
                worklist.push(rollup);
            }
            else {
                const state = new TreeState({root: receipts[i].publicInput.state.root, totalLiability: receipts[i].publicInput.state.totalLiability});
                const rollup = await RollupProver.toRollup(state, receipts[i]);
                worklist.push(rollup);
            }
        }

        while(worklist.length > 1) {
            let newWorklist = new Array<RollupProof>();
            for(let i = 0; i < worklist.length; i += 2) {
                if(worklist.length - i >= 2) {
                    const state = new TreeState({root: worklist[i].publicInput.root, totalLiability: worklist[i].publicInput.totalLiability});
                    const rollup = await RollupProver.mergeRollup(state, worklist[i], worklist[i + 1]);
                    newWorklist.push(rollup);
                }
                else {
                    newWorklist.push(worklist[i]);
                }
            }
            worklist = newWorklist;
        }

        if(worklist.length == 0) {
            throw new Error("No receipts given");
        }

        return worklist[0];
    }

    async finalize(feePayer: PrivateKey, tid: Field, rollup: RollupProof) {
        const lTree = this.tree.get(tid.toBigInt());
        const rTree = this.ref.get(tid.toBigInt());
        const curTotal = this.totLiability.get(tid.toBigInt());

        const chainRoot = lTree?.root.get();
        const chainLiability = lTree?.totalLiability.get();

        if(!lTree || !rTree || !curTotal || !chainRoot || !chainLiability) {
            throw new Error("Liability Tree Not Initialized");
        }

        let txn = await Mina.transaction(feePayer, () => {
            lTree.finalize(this.exchange, rollup);
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();
    
        if(rTree.getRoot().toBigInt() != lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync");
        }

        console.log("root: " + lTree.root.get());
    }

    async withdraw(feePayer: PrivateKey, req: Withdraw, sig: Signature) {
        const lTree = this.tree.get(req.tid.toBigInt());
        const rTree = this.ref.get(req.tid.toBigInt());
        const history = await this.getHistory(feePayer, req.tid, req.account);
        const curTotal = this.totLiability.get(req.tid.toBigInt());

        if(!lTree || !rTree || !history || !curTotal) {
            throw new Error("Liability Tree Not Initialized");
        }

        const index = this.getUserIndex(req.account);
        const prevLeaf = await this.getUserState(feePayer, req.tid, req.account);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const historyWit = new HistoryWitness(history.getWitness(prevLeaf.size.toBigInt()));

        let txn = await Mina.transaction(feePayer, () => {
            lTree.withdraw(this.exchange, req, sig, new LiabilityProof({leaf: prevLeaf, witness: witness}), historyWit);
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();
    
        history.setLeaf(prevLeaf.size.toBigInt(), req.prev);
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.sub(req.amount), eid: req.eid, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash())
        this.totLiability.set(req.tid.toBigInt(), curTotal.sub(req.amount));

        if(rTree.getRoot().toBigInt() != lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync, " + rTree.getRoot() + " vs " + lTree.root.get());
        }

        this.leaf.get(req.tid.toBigInt())?.set(req.account.toBase58(), nextLeaf);
    }

    async swapFrom(feePayer: PrivateKey, req: Swap, sig: Signature) {
        const lTree = this.tree.get(req.fromTid.toBigInt());
        const rTree = this.ref.get(req.fromTid.toBigInt());
        const history = await this.getHistory(feePayer, req.fromTid, req.account);
        const curTotal = this.totLiability.get(req.fromTid.toBigInt());

        if(!lTree || !rTree || !history || !curTotal) {
            throw new Error("Liability Tree Not Initialized");
        }

        const index = this.getUserIndex(req.account);
        const prevLeaf = await this.getUserState(feePayer, req.fromTid, req.account);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const historyWit = new HistoryWitness(history.getWitness(prevLeaf.size.toBigInt()));

        let txn = await Mina.transaction(feePayer, () => {
            lTree.swapFrom(this.exchange, req, sig, new LiabilityProof({leaf: prevLeaf, witness: witness}), historyWit);
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();
    
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.sub(req.fromAmount), eid: req.fromEid, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash());
        this.totLiability.set(req.fromTid.toBigInt(), curTotal.sub(req.fromAmount));

        if(rTree.getRoot().toBigInt() != lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync");
        }

        this.leaf.get(req.fromTid.toBigInt())?.set(req.account.toBase58(), nextLeaf);
    }

    async swapTo(feePayer: PrivateKey, req: Swap, sig: Signature) {
        const lTree = this.tree.get(req.toTid.toBigInt());
        const rTree = this.ref.get(req.toTid.toBigInt());
        const history = await this.getHistory(feePayer, req.toTid, req.account);
        const curTotal = this.totLiability.get(req.toTid.toBigInt());

        if(!lTree || !rTree || !history || !curTotal) {
            throw new Error("Liability Tree Not Initialized");
        }

        const index = this.getUserIndex(req.account);
        const prevLeaf = await this.getUserState(feePayer, req.toTid, req.account);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const historyWit = new HistoryWitness(history.getWitness(prevLeaf.size.toBigInt()));

        let txn = await Mina.transaction(feePayer, () => {
            lTree.swapTo(this.exchange, req, sig, new LiabilityProof({leaf: prevLeaf, witness: witness}), historyWit);
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();
    
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.add(req.toAmount), eid: req.toEid, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash())
        this.totLiability.set(req.toTid.toBigInt(), curTotal.add(req.toAmount));

        if(rTree.getRoot().toBigInt() != lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync");
        }

        this.leaf.get(req.toTid.toBigInt())?.set(req.account.toBase58(), nextLeaf);
    }
}

export async function randomDeposit(feePayer: PrivateKey, state: LiabilityState, keys: Array<PrivateKey>): Promise<[Deposit, Signature]> {
    let tokens = state.tids;
    let tid = tokens[Math.floor(Math.random() * tokens.length)];
    let key = keys[Math.floor(Math.random() * keys.length)];
    let leaf = await state.getUserState(feePayer, tid, key.toPublicKey());
    //Generated some numbers that were too large
    let amount = Field(Math.floor(Math.random() * 1000000000000))
    let prev = leaf.hash()
    let deposit = new Deposit({account: key.toPublicKey(), amount, eid: await state.getEid(tid), tid, prev})
    let sig = Signature.create(key, deposit.toFields())
    return [deposit, sig];
}

export async function randomWithdraw(feePayer: PrivateKey, state: LiabilityState, keys: Array<PrivateKey>): Promise<[Withdraw, Signature]> {
    const tokens = state.tids;
    const tid = tokens[Math.floor(Math.random() * tokens.length)];
    const key = keys[Math.floor(Math.random() * keys.length)];
    const leaf = await state.getUserState(feePayer, tid, key.toPublicKey());
    const amount = Field(Field.random().toBigInt() % (leaf.balance.toBigInt() + 1n));
    const prev = leaf.hash()
    const withdraw = new Withdraw({account: key.toPublicKey(), amount, eid: await state.getEid(tid), tid, prev})
    const sig = Signature.create(key, withdraw.toFields())
    return [withdraw, sig];
}

export async function randomSwap(feePayer: PrivateKey, state: LiabilityState, keys: Array<PrivateKey>) {
    // TODO: Likely need to update withdraw code.
}