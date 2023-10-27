import { Bool, Experimental, Field, MerkleWitness, Poseidon, PrivateKey, Proof, Provable, PublicKey, Reducer, SelfProof, Signature, SmartContract, State, Struct, method, state } from "o1js";

export const tid = Field(0);
export const users = {
    exchange: PrivateKey.random()
  };

export const LIABILITY_HEIGHT = 32;
export class LiabilityWitness extends MerkleWitness(LIABILITY_HEIGHT) {}

export const HISTORY_HEIGHT = 20; 
export class HistoryWitness extends MerkleWitness(HISTORY_HEIGHT) {}

export class LiabilityLeaf extends Struct({account: PublicKey, balance: Field, timestamp: Field, history: Field, size: Field}) {
    toFields(): Field[] {
        return [this.balance, this.timestamp, this.history, this.size].concat(this.account.toFields());
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class LiabilityProof extends Struct({leaf: LiabilityLeaf, witness: LiabilityWitness}) {}

export class Deposit extends Struct({account: PublicKey, amount: Field, timestamp: Field, tid: Field, prev: Field}) {
    toFields(): Field[] {
        return [Field(0xD390517), this.amount, this.prev, this.timestamp, this.tid].concat(this.account.toFields())
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class Withdraw extends Struct({account: PublicKey, amount: Field, timestamp: Field, tid: Field, prev: Field}) {
    toFields(): Field[] {
        return [Field(0x3174D4A3), this.amount, this.prev, this.timestamp, this.tid].concat(this.account.toFields())
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class Swap extends Struct({account: PublicKey, fromAmount: Field, toAmount: Field, timestamp: Field, toId: Field, fromId: Field, prevFrom: Field, prevTo: Field}) {
    toFields(): Field[] {
        return [Field(0x53A9), this.fromAmount, this.toAmount, this.timestamp, this.toId, this.fromId, this.prevFrom, this.prevTo].concat(this.account.toFields())
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
function processCreate(state: TreeState, proof: LiabilityProof): TreeState {
    proof.witness.calculateRoot(zeros[0]).assertEquals(state.root);
    proof.leaf.balance.assertEquals(0);
    proof.leaf.size.assertEquals(0);
    proof.leaf.history.assertEquals(zeros[HISTORY_HEIGHT - 1]);
    const newRoot = proof.witness.calculateRoot(proof.leaf.hash());
    return new TreeState({root: newRoot, totalLiability: state.totalLiability});
}

function processDeposit(state: TreeState, req: Deposit, proof: LiabilityProof, historyWit: HistoryWitness): TreeState {
    req.prev.assertNotEquals(Field(0));
    req.prev.equals(proof.leaf.hash())
    req.account.equals(proof.leaf.account)
    historyWit.calculateIndex().equals(proof.leaf.size);
    historyWit.calculateRoot(zeros[0]).equals(proof.leaf.history);
    proof.witness.calculateRoot(req.prev).assertEquals(state.root);
    req.tid.assertEquals(tid);

    let newBal = proof.leaf.balance.add(req.amount);
    let newSize = proof.leaf.size.add(1);
    let newHistory = historyWit.calculateRoot(req.prev)
    newBal.assertGreaterThanOrEqual(proof.leaf.balance);
    newBal.assertGreaterThanOrEqual(req.amount);
    let newLeaf:LiabilityLeaf = new LiabilityLeaf({account: req.account, balance: newBal, timestamp: req.timestamp, size: newSize, history: newHistory});
    let newRoot = proof.witness.calculateRoot(newLeaf.hash());
    let newTotal = state.totalLiability.add(req.amount);
    newLeaf.hash().assertNotEquals(Field(0))
    return new TreeState({root: newRoot, totalLiability: newTotal})
}

function processWithdraw(state: TreeState, req: Withdraw, proof: LiabilityProof, historyWit: HistoryWitness): TreeState {
    req.prev.assertNotEquals(0);
    req.prev.assertEquals(proof.leaf.hash());
    req.account.assertEquals(proof.leaf.account);
    historyWit.calculateIndex().equals(proof.leaf.size);
    historyWit.calculateRoot(zeros[0]).equals(proof.leaf.history);
    proof.witness.calculateRoot(req.prev).assertEquals(state.root);
    req.tid.assertEquals(tid);

    proof.leaf.balance.assertGreaterThanOrEqual(req.amount);

    let newBal = proof.leaf.balance.sub(req.amount);
    let newSize = proof.leaf.size.add(1);
    let newHistory = historyWit.calculateRoot(req.prev)
    let newLeaf:LiabilityLeaf = new LiabilityLeaf({account: req.account, balance: newBal, timestamp: req.timestamp, size: newSize, history: newHistory});
    let newRoot = proof.witness.calculateRoot(newLeaf.hash());
    let newTotal = state.totalLiability.sub(req.amount);
    newLeaf.hash().assertNotEquals(Field(0));
    return new TreeState({root: newRoot, totalLiability: newTotal});
}

export class ProofOutput extends Struct({state: TreeState, prover: PublicKey, latestTimestamp: Field}) {}
export const ActionProver = Experimental.ZkProgram({
    publicInput: TreeState,
    publicOutput: ProofOutput, // Add hash of leaf and public key?
    methods: {
        create: {
            //not currently validating the timestamp, something we can add in later
            privateInputs: [PrivateKey, LiabilityProof],
            method(start: TreeState, prover: PrivateKey, proof: LiabilityProof): ProofOutput {
                let newState = processCreate(start, proof);
                return new ProofOutput({state: newState, prover: prover.toPublicKey(), latestTimestamp: proof.leaf.timestamp})
            }
        },
        deposit: {
            privateInputs: [PrivateKey, Deposit, Signature, LiabilityProof, HistoryWitness],
            method(start: TreeState, prover: PrivateKey, req: Deposit, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness): ProofOutput {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let newState = processDeposit(start, req, proof, historyWit);
                return new ProofOutput({state: newState, prover: prover.toPublicKey(), latestTimestamp: req.timestamp})
            }
        },
        withdraw: {
            privateInputs: [PrivateKey, Withdraw, Signature, LiabilityProof, HistoryWitness],
            method(start: TreeState, prover: PrivateKey, req: Withdraw, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness): ProofOutput {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let newState = processWithdraw(start, req, proof, historyWit);
                return new ProofOutput({state: newState, prover: prover.toPublicKey(), latestTimestamp: req.timestamp})
            }
        },
        swapFrom: {
            privateInputs: [PrivateKey, Swap, Signature, LiabilityProof, HistoryWitness],
            method(start: TreeState, prover: PrivateKey, req: Swap, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness): ProofOutput {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true))
                let withdrawReq = new Withdraw({account: req.account, amount: req.fromAmount, timestamp: req.timestamp, tid: req.fromId, prev: req.prevFrom})
                let newState = processWithdraw(start, withdrawReq, proof, historyWit);
                return new ProofOutput({state: newState, prover: prover.toPublicKey(), latestTimestamp: req.timestamp})
            }
        },
        swapTo: {
            privateInputs: [PrivateKey, Swap, Signature, LiabilityProof, HistoryWitness],
            method(start: TreeState, prover: PrivateKey, req: Swap, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness): ProofOutput {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let depositReq = new Deposit({account: req.account, amount: req.toAmount, timestamp: req.timestamp, tid: req.toId, prev: req.prevTo});
                let newState = processDeposit(start, depositReq, proof, historyWit);
                return new ProofOutput({state: newState, prover: prover.toPublicKey(), latestTimestamp: req.timestamp})
            }
        }/*,
        merge: {
            privateInputs: [SelfProof, SelfProof],
            method(startState: TreeState, left: SelfProof<TreeState, ProofOutput>, right: SelfProof<TreeState, ProofOutput>): ProofOutput {
                left.verify();
                right.verify();
                right.publicOutput.latestTimestamp.assertGreaterThanOrEqual(left.publicOutput.latestTimestamp)
                startState.totalLiability.assertEquals(left.publicInput.totalLiability);
                startState.root.assertEquals(left.publicInput.root);
                left.publicOutput.state.root.assertEquals(right.publicInput.root);
                left.publicOutput.prover.assertEquals(right.publicOutput.prover);
                return right.publicOutput;
            }
        }*/
    }
});

export let ActionProof_ = Experimental.ZkProgram.Proof(ActionProver);
export class ActionProof extends ActionProof_ {}

export const RollupProver = Experimental.ZkProgram({
    publicInput: TreeState,
    publicOutput: ProofOutput, // Add hash of leaf and public key?
    methods: {
        mergeOps: {
            privateInputs: [ActionProof, ActionProof],
            method(startState: TreeState, left: ActionProof, right: ActionProof): ProofOutput {
                left.verify();
                right.verify();
                right.publicOutput.latestTimestamp.assertGreaterThanOrEqual(left.publicOutput.latestTimestamp)
                startState.totalLiability.assertEquals(left.publicInput.totalLiability);
                startState.root.assertEquals(left.publicInput.root);
                left.publicOutput.state.root.assertEquals(right.publicInput.root);
                left.publicOutput.prover.assertEquals(right.publicOutput.prover);
                return right.publicOutput;
            }
        },
        mergeRollup: {
            privateInputs: [SelfProof, SelfProof],
            method(startState: TreeState, left: SelfProof<TreeState, ProofOutput>, right: SelfProof<TreeState, ProofOutput>): ProofOutput {
                left.verify();
                right.verify();
                right.publicOutput.latestTimestamp.assertGreaterThanOrEqual(left.publicOutput.latestTimestamp)
                startState.totalLiability.assertEquals(left.publicInput.totalLiability);
                startState.root.assertEquals(left.publicInput.root);
                left.publicOutput.state.root.assertEquals(right.publicInput.root);
                left.publicOutput.prover.assertEquals(right.publicOutput.prover);
                return right.publicOutput;
            }
        }
    }
});

export let RollupProof_ = Experimental.ZkProgram.Proof(RollupProver);
export class RollupProof extends RollupProof_ {}

export class LiabilityTree extends SmartContract {
    //originally had tid as state, but I think we can keep that fixed
    @state(Field) root = State<Field>();
    @state(Field) latestTimestamp = State<Field>();
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
        this.latestTimestamp.set(Field(Date.now()))
        //this.actionState.set(Reducer.initialActionState);
        this.exchange.set(users['exchange'].toPublicKey())
    }

    @method create(key: PrivateKey, proof: LiabilityProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        let timestamp = this.network.timestamp.get();
        //not sure if this is required or not
        timestamp.assertEquals(this.network.timestamp.get());
        timestamp.value.assertGreaterThanOrEqual(proof.leaf.timestamp);

        let state = new TreeState({root, totalLiability});
        let newState = processCreate(state, proof);

        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
        this.latestTimestamp.set(timestamp.value);
    }

    @method deposit(key: PrivateKey, req: Deposit, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let latestTimestamp = this.latestTimestamp.get();
        this.latestTimestamp.assertEquals(latestTimestamp);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        let timestamp = this.network.timestamp.get();
        //not sure if this is required or not
        timestamp.assertEquals(this.network.timestamp.get());
        timestamp.value.assertGreaterThanOrEqual(req.timestamp);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let state = new TreeState({root, totalLiability});
        let newState = processDeposit(state, req, proof, historyWit);
        
        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
        this.latestTimestamp.set(Provable.if(latestTimestamp.lessThan(req.timestamp), Field, req.timestamp, latestTimestamp));
    }

    @method withdraw(key: PrivateKey, req: Withdraw, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let latestTimestamp = this.latestTimestamp.get();
        this.latestTimestamp.assertEquals(latestTimestamp);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        let timestamp = this.network.timestamp.get();
        //not sure if this is required or not
        timestamp.assertEquals(this.network.timestamp.get());
        timestamp.value.assertGreaterThanOrEqual(req.timestamp);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let state = new TreeState({root, totalLiability});
        let newState = processWithdraw(state, req, proof, historyWit);
        
        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
        this.latestTimestamp.set(Provable.if(latestTimestamp.lessThan(req.timestamp), Field, req.timestamp, latestTimestamp));
    }

    @method swapFrom(key: PrivateKey, req: Swap, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let latestTimestamp = this.latestTimestamp.get();
        this.latestTimestamp.assertEquals(latestTimestamp);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        let timestamp = this.network.timestamp.get();
        //not sure if this is required or not
        timestamp.assertEquals(this.network.timestamp.get());
        timestamp.value.assertGreaterThanOrEqual(req.timestamp);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true))
        let withdrawReq = new Withdraw({account: req.account, amount: req.fromAmount, timestamp: req.timestamp, tid: req.fromId, prev: req.prevFrom});
        let state = new TreeState({root, totalLiability});
        let newState = processWithdraw(state, withdrawReq, proof, historyWit);

        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
        this.latestTimestamp.set(Provable.if(latestTimestamp.lessThan(req.timestamp), Field, req.timestamp, latestTimestamp));
    }

    @method swapTo(key: PrivateKey, req: Swap, sig: Signature, proof: LiabilityProof, historyWit: HistoryWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let latestTimestamp = this.latestTimestamp.get();
        this.latestTimestamp.assertEquals(latestTimestamp);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        let timestamp = this.network.timestamp.get();
        //not sure if this is required or not
        timestamp.assertEquals(this.network.timestamp.get());
        timestamp.value.assertGreaterThanOrEqual(req.timestamp);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let depositReq = new Deposit({account: req.account, amount: req.toAmount, timestamp: req.timestamp, tid: req.toId, prev: req.prevTo});
        let state = new TreeState({root, totalLiability});
        let newState = processDeposit(state, depositReq, proof, historyWit);

        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability);
        this.latestTimestamp.set(Provable.if(latestTimestamp.lessThan(req.timestamp), Field, req.timestamp, latestTimestamp));
    }

    @method changeExchange(oldKey: PrivateKey, newKey: PrivateKey) {
        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        exchange.assertEquals(oldKey.toPublicKey());
        this.exchange.set(newKey.toPublicKey())
    }

    /*
     * The documentation here isn't good. I think I saw 3 different ways to specify the proof type and I'm
     * not certain which is correct. This one felt the most correct of all of them.
     */
    @method finalize(key: PrivateKey, proof: RollupProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let latestTimestamp = this.latestTimestamp.get();
        this.latestTimestamp.assertEquals(latestTimestamp);

        let timestamp = this.network.timestamp.get();
        //not sure if this is required or not
        timestamp.assertEquals(this.network.timestamp.get());

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        proof.verify();

        timestamp.value.assertGreaterThanOrEqual(proof.publicOutput.latestTimestamp);
        proof.publicOutput.prover.assertEquals(exchange);
        this.totalLiability.assertEquals(proof.publicInput.totalLiability);
        this.root.assertEquals(proof.publicInput.root);

        this.root.set(proof.publicOutput.state.root);
        this.totalLiability.set(proof.publicOutput.state.totalLiability);
        this.latestTimestamp.set(Provable.if(latestTimestamp.lessThan(proof.publicOutput.latestTimestamp), Field, proof.publicOutput.latestTimestamp, latestTimestamp));
    }

    // Allow a user to check in a proof if it was missing from the latest snapshot
    @method checkin(proof: RollupProof) {
        proof.verify();
    }

    // Allow a user to post a dispute which corresponds to branches in someone's history
    @method dispute(proof: RollupProof) {
        proof.verify();
    }

    /*@method refute() {

    }

    @method respond() {

    }

    @method resolve() {

    }

    @method finalize(key: PrivateKey, newRoot: Field, historyWitness: LiabilityWitness) {
        let eid = this.eid.get();
        this.eid.assertEquals(eid);

        let root = this.root.get();
        this.root.assertEquals(root);

        let historicRoot = this.historicRoot.get();
        this.historicRoot.assertEquals(historicRoot);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);

        key.toPublicKey().assertEquals(exchange);
        historyWitness.calculateIndex().assertEquals(eid);
        historyWitness.calculateRoot(this.zero(height - 1)).assertEquals(historicRoot);
        let newHistoricRoot = historyWitness.calculateRoot(root);

        this.root.set(newRoot);
        this.historicRoot.set(newHistoricRoot)
        this.eid.set(eid.add(1));
    }*/
}