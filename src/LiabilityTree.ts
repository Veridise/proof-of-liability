import { Bool, Field, MerkleWitness, Poseidon, PrivateKey, Proof, Provable, PublicKey, Reducer, SelfProof, Signature, SmartContract, State, Struct, UInt64, method, state, ZkProgram } from "o1js";

export const tid = Field(0);
export const users = {
    exchange: PrivateKey.random()
  };

export const LIABILITY_HEIGHT = 32;
export class LiabilityWitness extends MerkleWitness(LIABILITY_HEIGHT) {}

export const HISTORY_HEIGHT = 20; 
export class HistoryWitness extends MerkleWitness(HISTORY_HEIGHT) {}

export class LiabilityLeaf extends Struct({account: PublicKey, balance: Field, eid: Field, history: Field, size: Field}) {
    toFields(): Field[] {
        return [this.balance, this.eid, this.history, this.size].concat(this.account.toFields());
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class LiabilityProof extends Struct({leaf: LiabilityLeaf, witness: LiabilityWitness}) {}
export class HistoryProof extends Struct({leaf: LiabilityLeaf, witness: HistoryWitness}) {}

export class Deposit extends Struct({account: PublicKey, amount: Field, eid: Field, tid: Field, prev: Field}) {
    toFields(): Field[] {
        return [Field(0xD390517), this.amount, this.prev, this.eid, this.tid].concat(this.account.toFields())
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class Withdraw extends Struct({account: PublicKey, amount: Field, eid: Field, tid: Field, prev: Field}) {
    toFields(): Field[] {
        return [Field(0x3174D4A3), this.amount, this.prev, this.eid, this.tid].concat(this.account.toFields())
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class Swap extends Struct({account: PublicKey, fromAmount: Field, toAmount: Field, toEid: Field, fromEid: Field, toTid: Field, fromTid: Field, prevFrom: Field, prevTo: Field}) {
    toFields(): Field[] {
        return [Field(0x53A9), this.fromAmount, this.toAmount, this.toEid, this.fromEid, this.toTid, this.fromTid, this.prevFrom, this.prevTo].concat(this.account.toFields())
    }

    hash(): Field {
        return Poseidon.hash(this.toFields())
    }
}

export const zeros = [
    Field(0n),
    Field(21565680844461314807147611702860246336805372493508489110556896454939225549736n),
    Field(2447983280988565496525732146838829227220882878955914181821218085513143393976n),
    Field(544619463418997333856881110951498501703454628897449993518845662251180546746n),
    Field(20468198949394563802460512965219839480612000520504690501918527632215047268421n),
    Field(16556836945641263257329399459944072214107361158323688202689648863681494824075n),
    Field(15433636137932294330522564897643259724602670702144398296133714241278885195605n),
    Field(14472842460125086645444909368571209079194991627904749620726822601198914470820n),
    Field(21614416876217972474084851109688329000791937035724439964738173004620435920527n),
    Field(23396673455667782815008357063662227432928854130481827049177088579579506912772n),
    Field(16799216270319797546551726730220821530700130944535729528697378284641302758053n),
    Field(13496994890596928254174830027007320908142597452643688487140586680795895052589n),
    Field(3136367688481366987314253891173247447839122679172869317967104414474412425595n),
    Field(16414894720763442886261603851925762864778244212151669304308726942427436045416n),
    Field(22589430138891598861557640031858114956845676321373998952831060515802332123931n),
    Field(5791459643284782105200605043590392479676954402958680213128780189628932971164n),
    Field(16510281280427274356185141347114409143460588060107208117935011691496157196057n),
    Field(14486316384664676462434146886055824678546254125476991527791532204933765704550n),
    Field(25436453236035485996795240493313170211557120058262356001829805101279552630634n),
    Field(23937279336243536139305946754911463754843381541673857352836322740025067834219n),
    Field(19489292394622142448727235211662807700126173086870669586237893953121074753278n),
    Field(1945127946440409282447574121167141731006841597528804291507158560727071219394n),
    Field(27841935691558593279858640177961574373148122335514448527568736064618172266482n),
    Field(1451040666687561147253239281440678919270504603378145479495262585541545655751n),
    Field(7187408150830651995397647056737282096231806994914986672101145927009731216725n),
    Field(11229551900229640359517177371815132093008216997344565241557358240517857719286n),
    Field(27886982000707662952246192493114562530614536245180091951002749182300333355407n),
    Field(1632844294242046762372944946919354952116950207588688797662901656036050395190n),
    Field(8701831002808487708010013192668392046494553722610567204400859611275815400103n),
    Field(25402475059779170105587548815107802022608986787228538009148795372505931547773n),
    Field(27386122974213259186011953850211857692042705064305347934338306205477491590350n),
    Field(19057105225525447794058879360670244229202611178388892366137113354909512903676n)
    ];

export class TreeState extends Struct({root: Field, totalLiability: Field}) {}
/*
 * Switched from the model where deposit could automatically allocate an account to 
 *  simplify code and prevent potential tricks.
 */
function processCreate(state: TreeState, witness: LiabilityWitness, leaf: LiabilityLeaf): TreeState {
    witness.calculateRoot(zeros[0]).assertEquals(state.root);
    leaf.balance.assertEquals(0);
    leaf.size.assertEquals(0);
    leaf.history.assertEquals(zeros[HISTORY_HEIGHT - 1]);
    const newRoot = witness.calculateRoot(leaf.hash());
    return new TreeState({root: newRoot, totalLiability: state.totalLiability});
}

function processDeposit(state: TreeState, req: Deposit, witness: LiabilityWitness, leaf: LiabilityLeaf, historyWit: HistoryWitness): TreeState {
    req.prev.assertNotEquals(Field(0));
    req.prev.equals(leaf.hash())
    req.account.equals(leaf.account)
    historyWit.calculateIndex().equals(leaf.size);
    historyWit.calculateRoot(zeros[0]).equals(leaf.history);
    witness.calculateRoot(req.prev).assertEquals(state.root);
    req.tid.assertEquals(tid);

    let newBal = leaf.balance.add(req.amount);
    let newSize = leaf.size.add(1);
    let newHistory = historyWit.calculateRoot(req.prev)
    newBal.assertGreaterThanOrEqual(leaf.balance);
    newBal.assertGreaterThanOrEqual(req.amount);
    let newLeaf:LiabilityLeaf = new LiabilityLeaf({account: req.account, balance: newBal, eid: req.eid, size: newSize, history: newHistory});
    let newRoot = witness.calculateRoot(newLeaf.hash());
    let newTotal = state.totalLiability.add(req.amount);
    newLeaf.hash().assertNotEquals(Field(0))
    return new TreeState({root: newRoot, totalLiability: newTotal})
}

function processWithdraw(state: TreeState, req: Withdraw, witness: LiabilityWitness, leaf: LiabilityLeaf, historyWit: HistoryWitness): TreeState {
    req.prev.assertNotEquals(0);
    req.prev.assertEquals(leaf.hash());
    req.account.assertEquals(leaf.account);
    historyWit.calculateIndex().equals(leaf.size);
    historyWit.calculateRoot(zeros[0]).equals(leaf.history);
    witness.calculateRoot(req.prev).assertEquals(state.root);
    req.tid.assertEquals(tid);

    leaf.balance.assertGreaterThanOrEqual(req.amount);

    let newBal = leaf.balance.sub(req.amount);
    let newSize = leaf.size.add(1);
    let newHistory = historyWit.calculateRoot(req.prev)
    let newLeaf:LiabilityLeaf = new LiabilityLeaf({account: req.account, balance: newBal, eid: req.eid, size: newSize, history: newHistory});
    let newRoot = witness.calculateRoot(newLeaf.hash());
    let newTotal = state.totalLiability.sub(req.amount);
    newLeaf.hash().assertNotEquals(Field(0));
    return new TreeState({root: newRoot, totalLiability: newTotal});
}

export class ReceiptInput extends Struct({state: TreeState, witness: LiabilityWitness}) {}
export class ReceiptOutput extends Struct({state: TreeState, prover: PublicKey, eid: Field}) {}
export const ReceiptProver = ZkProgram({
    name: "Receipt",
    publicInput: ReceiptInput,
    publicOutput: ReceiptOutput, // Add hash of leaf and public key?
    methods: {
        create: {
            //not currently validating the timestamp, something we can add in later
            privateInputs: [PrivateKey, LiabilityLeaf],
            method(pub: ReceiptInput, prover: PrivateKey, leaf: LiabilityLeaf): ReceiptOutput {
                let newState = processCreate(pub.state, pub.witness, leaf);
                return new ReceiptOutput({state: newState, prover: prover.toPublicKey(), eid: leaf.eid})
            }
        },
        deposit: {
            privateInputs: [PrivateKey, Deposit, Signature, LiabilityLeaf, HistoryWitness],
            method(pub: ReceiptInput, prover: PrivateKey, req: Deposit, sig: Signature, leaf: LiabilityLeaf, historyWit: HistoryWitness): ReceiptOutput {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let newState = processDeposit(pub.state, req, pub.witness, leaf, historyWit);
                return new ReceiptOutput({state: newState, prover: prover.toPublicKey(), eid: leaf.eid})
            }
        },
        withdraw: {
            privateInputs: [PrivateKey, Withdraw, Signature, LiabilityLeaf, HistoryWitness],
            method(pub: ReceiptInput, prover: PrivateKey, req: Withdraw, sig: Signature, leaf: LiabilityLeaf, historyWit: HistoryWitness): ReceiptOutput {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let newState = processWithdraw(pub.state, req, pub.witness, leaf, historyWit);
                return new ReceiptOutput({state: newState, prover: prover.toPublicKey(), eid: leaf.eid})
            }
        },
        swapFrom: {
            privateInputs: [PrivateKey, Swap, Signature, LiabilityLeaf, HistoryWitness],
            method(pub: ReceiptInput, prover: PrivateKey, req: Swap, sig: Signature, leaf: LiabilityLeaf, historyWit: HistoryWitness): ReceiptOutput {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true))
                let withdrawReq = new Withdraw({account: req.account, amount: req.fromAmount, eid: req.fromEid, tid: req.fromTid, prev: req.prevFrom})
                let newState = processWithdraw(pub.state, withdrawReq, pub.witness, leaf, historyWit);
                return new ReceiptOutput({state: newState, prover: prover.toPublicKey(), eid: leaf.eid})
            }
        },
        swapTo: {
            privateInputs: [PrivateKey, Swap, Signature, LiabilityLeaf, HistoryWitness],
            method(pub: ReceiptInput, prover: PrivateKey, req: Swap, sig: Signature, leaf: LiabilityLeaf, historyWit: HistoryWitness): ReceiptOutput {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let depositReq = new Deposit({account: req.account, amount: req.toAmount, eid: req.toEid, tid: req.toTid, prev: req.prevTo});
                let newState = processDeposit(pub.state, depositReq, pub.witness, leaf, historyWit);
                return new ReceiptOutput({state: newState, prover: prover.toPublicKey(), eid: leaf.eid})
            }
        }
    }
});

export let ReceiptProof_ = ZkProgram.Proof(ReceiptProver);
export class ReceiptProof extends ReceiptProof_ {}
export class RollupOutput extends Struct({state: TreeState, prover: PublicKey, eid: Field}) {}

export const RollupProver = ZkProgram({
    name: "Rollup",
    publicInput: TreeState,
    publicOutput: RollupOutput, // Add hash of leaf and public key?
    methods: {
        toRollup: {
            privateInputs: [ReceiptProof],
            method(startState: TreeState, receipt: ReceiptProof): RollupOutput {
                receipt.verify();
                startState.totalLiability.assertEquals(receipt.publicInput.state.totalLiability);
                startState.root.assertEquals(receipt.publicInput.state.root);
                const out = new RollupOutput({state: receipt.publicOutput.state, prover: receipt.publicOutput.prover, eid: receipt.publicOutput.eid})
                return out;
            }
        },
        mergeReceipts: {
            privateInputs: [ReceiptProof, ReceiptProof],
            method(startState: TreeState, left: ReceiptProof, right: ReceiptProof): RollupOutput {
                left.verify();
                right.verify();
                startState.totalLiability.assertEquals(left.publicInput.state.totalLiability);
                startState.root.assertEquals(left.publicInput.state.root);
                left.publicOutput.state.root.assertEquals(right.publicInput.state.root);
                left.publicOutput.state.totalLiability.assertEquals(right.publicInput.state.totalLiability);
                left.publicOutput.prover.assertEquals(right.publicOutput.prover);
                right.publicOutput.eid.assertEquals(left.publicOutput.eid);
                const out = new RollupOutput({state: right.publicOutput.state, prover: left.publicOutput.prover, eid: left.publicOutput.eid});
                return out;
            }
        },
        mergeRollup: {
            privateInputs: [SelfProof, SelfProof],
            method(startState: TreeState, left: SelfProof<TreeState, RollupOutput>, right: SelfProof<TreeState, RollupOutput>): RollupOutput {
                left.verify();
                right.verify();
                startState.totalLiability.assertEquals(left.publicInput.totalLiability);
                startState.root.assertEquals(left.publicInput.root);
                left.publicOutput.state.root.assertEquals(right.publicInput.root);
                left.publicOutput.state.totalLiability.assertEquals(right.publicInput.totalLiability);
                left.publicOutput.prover.assertEquals(right.publicOutput.prover);
                right.publicOutput.eid.assertEquals(left.publicOutput.eid);
                const out = new RollupOutput({state: right.publicOutput.state, prover: left.publicOutput.prover, eid: left.publicOutput.eid});
                return out;
            }
        }
    }
});

export let RollupProof_ = ZkProgram.Proof(RollupProver);
export class RollupProof extends RollupProof_ {}

export class DisputeBranch extends Struct({index: Field, historyHash: Field, altHash: Field}) {}

export class LiabilityTree extends SmartContract {
    events = {
        "Disputed": DisputeBranch,
    }

    //originally had tid as state, but I think we can keep that fixed
    @state(Field) root = State<Field>();
    @state(Field) eid = State<Field>();
    @state(PublicKey) exchange = State<PublicKey>();
    @state(Field) totalLiability = State<Field>();

    reducer = Reducer({actionType: Field});

    zero(i: number): Field {
        // TODO: Ask if this is safe
        return zeros[i];
    }

    init() {
        super.init();
        let zeroRoot = this.zero(LIABILITY_HEIGHT - 1);
        this.root.set(zeroRoot);
        this.eid.set(Field(0));
        //this.actionState.set(Reducer.initialActionState);
        this.exchange.set(users['exchange'].toPublicKey())
    }

    @method create(key: PrivateKey, proof: LiabilityProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let eid = this.eid.get();
        this.eid.assertEquals(eid);
        eid.assertEquals(proof.leaf.eid);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        let state = new TreeState({root, totalLiability});
        let newState = processCreate(state, proof.witness, proof.leaf);

        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
    }

    @method deposit(key: PrivateKey, req: Deposit, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let eid = this.eid.get();
        this.eid.assertEquals(eid);
        eid.assertEquals(proof.leaf.eid);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let state = new TreeState({root, totalLiability});
        let newState = processDeposit(state, req, proof.witness, proof.leaf, historyWit);
        
        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
    }

    @method withdraw(key: PrivateKey, req: Withdraw, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let eid = this.eid.get();
        this.eid.assertEquals(eid);
        eid.assertEquals(proof.leaf.eid);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let state = new TreeState({root, totalLiability});
        let newState = processWithdraw(state, req, proof.witness, proof.leaf, historyWit);
        
        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
    }

    @method swapFrom(key: PrivateKey, req: Swap, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let eid = this.eid.get();
        this.eid.assertEquals(eid);
        eid.assertEquals(proof.leaf.eid);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true))
        let withdrawReq = new Withdraw({account: req.account, amount: req.fromAmount, eid: req.fromEid, tid: req.fromTid, prev: req.prevFrom});
        let state = new TreeState({root, totalLiability});
        let newState = processWithdraw(state, withdrawReq, proof.witness, proof.leaf, historyWit);

        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
    }

    @method swapTo(key: PrivateKey, req: Swap, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let eid = this.eid.get();
        this.eid.assertEquals(eid);
        eid.assertEquals(proof.leaf.eid);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let depositReq = new Deposit({account: req.account, amount: req.toAmount, eid: req.toEid, tid: req.toTid, prev: req.prevTo});
        let state = new TreeState({root, totalLiability});
        let newState = processDeposit(state, depositReq, proof.witness, proof.leaf, historyWit);

        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
    }

    @method changeExchange(oldKey: PrivateKey, newKey: PrivateKey) {
        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        exchange.assertEquals(oldKey.toPublicKey());
        this.exchange.set(newKey.toPublicKey())
    }

    @method finalize(key: PrivateKey, proof: RollupProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let eid = this.eid.get();
        this.eid.assertEquals(eid);
        eid.assertEquals(proof.publicOutput.eid);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        proof.verify();

        proof.publicOutput.prover.assertEquals(exchange);
        this.totalLiability.assertEquals(proof.publicInput.totalLiability);
        this.root.assertEquals(proof.publicInput.root);

        this.root.set(proof.publicOutput.state.root);
        this.totalLiability.set(proof.publicOutput.state.totalLiability);
        this.eid.set(eid.add(Field(1)))
    }

    // Allow a user to check in a proof if it was missing from the latest snapshot
    @method checkin(proof: ReceiptProof, curLiability: LiabilityProof, newLeaf: LiabilityLeaf, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let eid = this.eid.get();
        this.eid.assertEquals(eid);

        // Proofs checked in after this proof
        eid.assertGreaterThan(proof.publicOutput.eid);

        // Proof is valid
        proof.verify();

        // Proof came from the exchange
        proof.publicOutput.prover.assertEquals(exchange);

        // Current leaf is in current liability tree
        const prevHash = curLiability.leaf.hash();
        curLiability.witness.calculateRoot(prevHash).assertEquals(root);

        // New Liability in proof root
        const newHash = newLeaf.hash();
        proof.publicInput.witness.calculateRoot(newHash).assertEquals(proof.publicInput.state.root);

        // Same index is being referenced
        proof.publicInput.witness.calculateIndex().assertEquals(curLiability.witness.calculateIndex());

        // Proven leaf is next in history
        newLeaf.history.assertEquals(historyWit.calculateRoot(prevHash));
        newLeaf.size.assertEquals(curLiability.leaf.size.add(1))

        //update
        const newRoot = curLiability.witness.calculateRoot(newHash);
        const newTotal = totalLiability.add(newLeaf.balance.sub(curLiability.leaf.balance));

        this.root.set(newRoot);
        this.totalLiability.set(newTotal);
    }

    // Allow a user to post a dispute which corresponds to branches in someone's history
    @method dispute(proof: ReceiptProof, curLiability: LiabilityProof, branchProof: HistoryProof, altLeaf: LiabilityLeaf) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        // Proof is valid
        proof.verify();

        // Proof came from the exchange
        proof.publicOutput.prover.assertEquals(exchange);

        // cur leaf is in current liability tree
        const prevHash = curLiability.leaf.hash();
        curLiability.witness.calculateRoot(prevHash).assertEquals(root);

        // New Liability in proof root
        const newHash = altLeaf.hash();
        proof.publicInput.witness.calculateRoot(newHash).assertEquals(proof.publicInput.state.root);

        // Same index is being referenced
        proof.publicInput.witness.calculateIndex().assertEquals(curLiability.witness.calculateIndex());

        // Prove historyLeaf is in history of current leaf
        const branchHash = branchProof.leaf.hash();
        branchProof.witness.calculateRoot(branchHash).assertEquals(curLiability.leaf.history)

        // Prove historyLeaf and altLeaf have the same root and size
        branchProof.leaf.history.assertEquals(altLeaf.history);
        branchProof.leaf.size.assertEquals(altLeaf.size);

        // Leaves are not the same
        const altHash = altLeaf.hash();
        branchHash.assertNotEquals(altHash);

        this.emitEvent("Disputed", new DisputeBranch({index: altLeaf.size, historyHash: branchHash, altHash: altHash}));
    }
}