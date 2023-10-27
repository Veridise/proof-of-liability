import { AccountUpdate, Field, MerkleTree, Mina, PrivateKey, PublicKey, Signature, UInt32, UInt64 } from 'o1js';
import { Deposit, LiabilityTree, HistoryWitness, LiabilityProof, LiabilityLeaf, LiabilityWitness, users, RollupProof, RollupProver, Withdraw, Swap, LIABILITY_HEIGHT, HISTORY_HEIGHT, zeros } from '../LiabilityTree';
import { MerkleProof } from '../IncrementalMerkleTree';

export class LiabilityState {
    tids: Array<Field>;
    tree: Map<Field, LiabilityTree>;
    ref: Map<Field, MerkleTree>;
    leaf: Map<Field, Map<PublicKey, LiabilityLeaf>>;
    treeIndex: Map<PublicKey, bigint>;
    histories: Map<Field, Map<PublicKey, MerkleTree>>;
    usedIds = new Set<bigint>();
    exchange: PrivateKey;

    constructor() {
        this.tids = new Array<Field>();
        this.tree = new Map<Field, LiabilityTree>();
        this.ref = new Map<Field, MerkleTree>();
        this.leaf = new Map<Field, Map<PublicKey, LiabilityLeaf>>();
        this.treeIndex = new Map<PublicKey, bigint>();
        this.usedIds = new Set<bigint>();
        this.exchange = users['exchange'];
        this.histories = new Map<Field, Map<PublicKey, MerkleTree>>();
    }

    tokens(): Array<Field> {
        return this.tids;
    }

    getTimestamp(): Field{
        return Field(Date.now())
    }

    async getUserState(feePayer: PrivateKey, id: Field, key: PublicKey): Promise<LiabilityLeaf> {
        const leaf = this.leaf.get(id)?.get(key);
        if(leaf) {
            return leaf;
        }

        const rTree = this.ref.get(id);
        const lTree = this.tree.get(id);
        if(!rTree || !lTree) {
            throw new Error("Undefined reference tree")
        }
        const index = this.getUserIndex(key);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const newLeaf = new LiabilityLeaf({account: key, balance: Field(0), timestamp: this.getTimestamp(), history: zeros[HISTORY_HEIGHT - 1], size: Field(0)})

        let txn = await Mina.transaction(feePayer, () => {
            lTree.create(this.exchange, new LiabilityProof({witness, leaf: newLeaf}))
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();

        rTree.setLeaf(index, newLeaf.hash());
        const history = new MerkleTree(HISTORY_HEIGHT);
        this.histories.get(id)?.set(key, history);
        return newLeaf;
    }

    async getHistory(feePayer: PrivateKey, id: Field, key: PublicKey): Promise<MerkleTree> {
        let history = this.histories.get(id)?.get(key);
        if(history) {
            return history;
        }

        const leaf = await this.getUserState(feePayer, id, key);
        history = this.histories.get(id)?.get(key);
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

        this.tree.set(id, newTree);
        this.ref.set(id, refTree);
        this.leaf.set(id, new Map<PublicKey, LiabilityLeaf>());
        this.histories.set(id, new Map<PublicKey, MerkleTree>());
        this.tids.push(id);
    }

    getUserIndex(key: PublicKey): bigint {
        let index = this.treeIndex.get(key);
        if(index) {
            return index;
        }

        let id = BigInt(Math.round(Math.random() * (2 ** (LIABILITY_HEIGHT - 1))));
        while(this.usedIds.has(id)) {
            id = BigInt(Math.round(Math.random() * (2 ** (LIABILITY_HEIGHT - 1))));
        }
        this.usedIds.add(id);
        this.treeIndex.set(key, id);

        return id;
    }

    async deposit(feePayer: PrivateKey, req: Deposit, sig: Signature) {
        const lTree = this.tree.get(req.tid);
        const rTree = this.ref.get(req.tid);
        const history = await this.getHistory(feePayer, req.tid, req.account);

        if(!lTree || !rTree || !history) {
            return;
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
    
        history.setLeaf(prevLeaf.size.toBigInt(), prevLeaf.hash())
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.add(req.amount), timestamp: req.timestamp, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash())

        if(rTree.getRoot().toBigInt() == lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync");
        }

        this.leaf.get(req.tid)?.set(req.account, nextLeaf);
        console.log("lroot: " + lTree.root.get());
        console.log("rroot: " + rTree.getRoot());
    }

    async withdraw(feePayer: PrivateKey, req: Withdraw, sig: Signature) {
        const lTree = this.tree.get(req.tid);
        const rTree = this.ref.get(req.tid);
        const history = await this.getHistory(feePayer, req.tid, req.account);

        if(!lTree || !rTree || !history) {
            return;
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
    
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.sub(req.amount), timestamp: req.timestamp, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash())

        if(rTree.getRoot().toBigInt() == lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync");
        }

        this.leaf.get(req.tid)?.set(req.account, nextLeaf);
    }

    async swapFrom(feePayer: PrivateKey, req: Swap, sig: Signature) {
        const lTree = this.tree.get(req.fromId);
        const rTree = this.ref.get(req.fromId);
        const history = await this.getHistory(feePayer, req.fromId, req.account);

        if(!lTree || !rTree || !history) {
            return;
        }

        const index = this.getUserIndex(req.account);
        const prevLeaf = await this.getUserState(feePayer, req.fromId, req.account);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const historyWit = new HistoryWitness(history.getWitness(prevLeaf.size.toBigInt()));

        let txn = await Mina.transaction(feePayer, () => {
            lTree.swapFrom(this.exchange, req, sig, new LiabilityProof({leaf: prevLeaf, witness: witness}), historyWit);
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();
    
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.sub(req.fromAmount), timestamp: req.timestamp, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash())

        if(rTree.getRoot().toBigInt() == lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync");
        }

        this.leaf.get(req.fromId)?.set(req.account, nextLeaf);
    }

    async swapTo(feePayer: PrivateKey, req: Swap, sig: Signature) {
        const lTree = this.tree.get(req.toId);
        const rTree = this.ref.get(req.toId);
        const history = await this.getHistory(feePayer, req.toId, req.account);

        if(!lTree || !rTree || !history) {
            return;
        }

        const index = this.getUserIndex(req.account);
        const prevLeaf = await this.getUserState(feePayer, req.toId, req.account);
        const witness = new LiabilityWitness(rTree.getWitness(index));
        const historyWit = new HistoryWitness(history.getWitness(prevLeaf.size.toBigInt()));

        let txn = await Mina.transaction(feePayer, () => {
            lTree.swapTo(this.exchange, req, sig, new LiabilityProof({leaf: prevLeaf, witness: witness}), historyWit);
        });
    
        await txn.prove()
        await txn.sign([this.exchange]).send();
    
        let nextLeaf = new LiabilityLeaf({account: req.account, balance: prevLeaf.balance.add(req.toAmount), timestamp: req.timestamp, history: history.getRoot(), size: prevLeaf.size.add(1)});
        rTree.setLeaf(index, nextLeaf.hash())

        if(rTree.getRoot().toBigInt() == lTree.root.get().toBigInt()) {
            throw new Error("Reference tree is out of sync");
        }

        this.leaf.get(req.toId)?.set(req.account, nextLeaf);
    }
}

export async function randomDeposit(feePayer: PrivateKey, state: LiabilityState, keys: Array<PrivateKey>): Promise<[Deposit, Signature]> {
    let tokens = state.tids;
    let tid = tokens[Math.floor(Math.random() * tokens.length)];
    let key = keys[Math.floor(Math.random() * keys.length)];
    let leaf = await state.getUserState(feePayer, tid, key.toPublicKey());
    //Generated some numbers that were too large
    let amount = Field(Math.floor(Math.random() * 1000000000000))
    let prev = leaf.account.isEmpty() ? Field(0) : leaf.hash()
    const timestamp = Field(Date.now());
    let deposit = new Deposit({account: key.toPublicKey(), amount, timestamp, tid, prev})
    let sig = Signature.create(key, deposit.toFields())
    return [deposit, sig];
}

export async function randomWithdraw(feePayer: PrivateKey, state: LiabilityState, keys: Array<PrivateKey>): Promise<[Withdraw, Signature]> {
    const tokens = state.tids;
    const tid = tokens[Math.floor(Math.random() * tokens.length)];
    const key = keys[Math.floor(Math.random() * keys.length)];
    const leaf = await state.getUserState(feePayer, tid, key.toPublicKey());
    const amount = Field(Field.random().toBigInt() % (leaf.balance.toBigInt() + 1n));
    const prev = leaf.account.isEmpty() ? Field(0) : leaf.hash()
    const timestamp = Field(Date.now());
    const withdraw = new Withdraw({account: key.toPublicKey(), amount, timestamp, tid, prev})
    const sig = Signature.create(key, withdraw.toFields())
    return [withdraw, sig];
}

export async function randomSwap(feePayer: PrivateKey, state: LiabilityState, keys: Array<PrivateKey>) {
    // TODO: Likely need to update withdraw code.
}