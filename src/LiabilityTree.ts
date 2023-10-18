import { Bool, Experimental, Field, MerkleWitness, Poseidon, PrivateKey, Proof, Provable, PublicKey, Reducer, SelfProof, Signature, SmartContract, State, Struct, method, state } from "o1js";

export const tid = Field(0);
export const users = {
    exchange: PrivateKey.random()
  };

const height = 32;
export class LiabilityWitness extends MerkleWitness(height) {}

export class LiabilityLeaf extends Struct({account: PublicKey, balance: Field, prev: Field}) {
    toFields(): Field[] {
        return [this.balance, this.prev].concat(this.account.toFields());
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class LiabilityProof extends Struct({leaf: LiabilityLeaf, witness: LiabilityWitness}) {

}

export class Deposit extends Struct({account: PublicKey, amount: Field, tid: Field, prev: Field}) {
    toFields(): Field[] {
        return [this.amount, this.prev, this.tid].concat(this.account.toFields())
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class Withdraw extends Struct({account: PublicKey, amount: Field, tid: Field, prev: Field}) {
    toFields(): Field[] {
        return [this.amount, this.prev, this.tid].concat(this.account.toFields())
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

export class Swap extends Struct({account: PublicKey, fromAmount: Field, toAmount: Field, toId: Field, fromId: Field, prevFrom: Field, prevTo: Field}) {
    toFields(): Field[] {
        return [this.fromAmount, this.toAmount, this.toId, this.fromId, this.prevFrom, this.prevTo].concat(this.account.toFields())
    }

    hash(): Field {
        return Poseidon.hash(this.toFields())
    }
}

const zeros = [
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
function processDeposit(state: TreeState, req: Deposit, sig: Signature, proof: LiabilityProof): TreeState {
    req.prev.equals(0).or(req.prev.equals(proof.leaf.hash())).assertTrue();
    req.prev.equals(0).or(req.account.equals(proof.leaf.account)).assertTrue();
    proof.witness.calculateRoot(req.prev).assertEquals(state.root);
    req.tid.assertEquals(tid);

    let oldBal = Provable.if(req.prev.equals(0), Field, Field(0), proof.leaf.balance);

    let newBal = oldBal.add(req.amount);
    newBal.assertGreaterThanOrEqual(oldBal);
    newBal.assertGreaterThanOrEqual(req.amount);
    let newLeaf:LiabilityLeaf = new LiabilityLeaf({account: req.account, balance: newBal, prev: req.prev});
    let newRoot = proof.witness.calculateRoot(newLeaf.hash());
    let newTotal = state.totalLiability.add(req.amount);
    return new TreeState({root: newRoot, totalLiability: newTotal})
}

function processWithdraw(state: TreeState, req: Withdraw, sig: Signature, proof: LiabilityProof): TreeState {
    req.prev.assertNotEquals(0);
    req.prev.assertEquals(proof.leaf.hash());
    req.account.assertEquals(proof.leaf.account);
    proof.witness.calculateRoot(req.prev).assertEquals(state.root);
    req.tid.assertEquals(tid);

    proof.leaf.balance.assertGreaterThanOrEqual(req.amount);

    let newBal = proof.leaf.balance.sub(req.amount);
    let newLeaf:LiabilityLeaf = new LiabilityLeaf({account: req.account, balance: newBal, prev: req.prev});
    let newRoot = proof.witness.calculateRoot(newLeaf.hash());
    let newTotal = state.totalLiability.sub(req.amount);
    return new TreeState({root: newRoot, totalLiability: newTotal});
}

export const RollupProver = Experimental.ZkProgram({
    publicInput: TreeState,
    publicOutput: TreeState,
    methods: {
        deposit: {
            privateInputs: [Deposit, Signature, LiabilityProof],
            method(start: TreeState, req: Deposit, sig: Signature, proof: LiabilityProof): TreeState {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let newState = processDeposit(start, req, sig, proof);
                return newState;
            }
        },
        withdraw: {
            privateInputs: [Withdraw, Signature, LiabilityProof],
            method(start: TreeState, req: Withdraw, sig: Signature, proof: LiabilityProof): TreeState {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let newState = processWithdraw(start, req, sig, proof);
                return newState
            }
        },
        swapFrom: {
            privateInputs: [Swap, Signature, LiabilityProof],
            method(start: TreeState, req: Swap, sig: Signature, proof: LiabilityProof): TreeState {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true))
                let withdrawReq = new Withdraw({account: req.account, amount: req.fromAmount, tid: req.fromId, prev: req.prevFrom})
                let newState = processWithdraw(start, withdrawReq, sig, proof);
                return newState
            }
        },
        swapTo: {
            privateInputs: [Swap, Signature, LiabilityProof],
            method(start: TreeState, req: Swap, sig: Signature, proof: LiabilityProof): TreeState {
                sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
                let depositReq = new Deposit({account: req.account, amount: req.toAmount, tid: req.toId, prev: req.prevTo});
                let newState = processDeposit(start, depositReq, sig, proof);
                return newState
            }
        },
        /*batch8: {
            privateInputs: [SelfProof, SelfProof, SelfProof, SelfProof, SelfProof, SelfProof, SelfProof, SelfProof],
            method(startState: TreeState, l1: SelfProof<TreeState, TreeState>, l2: SelfProof<TreeState, TreeState>, l3: SelfProof<TreeState, TreeState>, l4: SelfProof<TreeState, TreeState>, l5: SelfProof<TreeState, TreeState>, l6: SelfProof<TreeState, TreeState>, l7: SelfProof<TreeState, TreeState>, l8: SelfProof<TreeState, TreeState>): TreeState {
                l1.verify();
                l2.verify();
                l3.verify();
                l4.verify();
                l5.verify();
                l6.verify();
                l7.verify();
                l8.verify();
                startState.root.assertEquals(l1.publicInput.root);
                l1.publicOutput.root.assertEquals(l2.publicInput.root);
                l2.publicOutput.root.assertEquals(l3.publicInput.root);
                l3.publicOutput.root.assertEquals(l4.publicInput.root);
                l4.publicOutput.root.assertEquals(l5.publicInput.root);
                l5.publicOutput.root.assertEquals(l6.publicInput.root);
                l6.publicOutput.root.assertEquals(l7.publicInput.root);
                l7.publicOutput.root.assertEquals(l8.publicInput.root);
                return l8.publicOutput;
            }
        },
        batch4: {
            privateInputs: [SelfProof, SelfProof, SelfProof, SelfProof],
            method(startState: TreeState, l1: SelfProof<TreeState, TreeState>, l2: SelfProof<TreeState, TreeState>, l3: SelfProof<TreeState, TreeState>, l4: SelfProof<TreeState, TreeState>): TreeState {
                l1.verify();
                l2.verify();
                l3.verify();
                l4.verify();
                startState.root.assertEquals(l1.publicInput.root);
                l1.publicOutput.root.assertEquals(l2.publicInput.root);
                l2.publicOutput.root.assertEquals(l3.publicInput.root);
                l3.publicOutput.root.assertEquals(l4.publicInput.root);
                return l4.publicOutput;
            }
        },*/
        merge: {
            privateInputs: [SelfProof, SelfProof],
            method(startState: TreeState, left: SelfProof<TreeState, TreeState>, right: SelfProof<TreeState, TreeState>): TreeState {
                left.verify();
                right.verify();
                startState.root.assertEquals(left.publicInput.root);
                left.publicOutput.root.assertEquals(right.publicInput.root);
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
    @state(Field) actionState = State<Field>();
    @state(PublicKey) exchange = State<PublicKey>();
    @state(Field) totalLiability = State<Field>();

    reducer = Reducer({actionType: Field});

    zero(i: number): Field {
        // TODO: Ask if this is safe
        return zeros[i];
    }

    init() {
        super.init();
        let zeroRoot = this.zero(height - 1);
        this.root.set(zeroRoot);
        this.actionState.set(Reducer.initialActionState);
        this.exchange.set(users['exchange'].toPublicKey())
    }

    @method deposit(key: PrivateKey, req: Deposit, sig: Signature, proof: LiabilityProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let state = new TreeState({root, totalLiability});
        let newState = processDeposit(state, req, sig, proof);
        
        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability)
    }

    @method withdraw(key: PrivateKey, req: Withdraw, sig: Signature, proof: LiabilityProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let state = new TreeState({root, totalLiability});
        let newState = processWithdraw(state, req, sig, proof);
        
        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability)
    }

    @method swapFrom(key: PrivateKey, req: Swap, sig: Signature, proof: LiabilityProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true))
        let withdrawReq = new Withdraw({account: req.account, amount: req.fromAmount, tid: req.fromId, prev: req.prevFrom});
        let state = new TreeState({root, totalLiability});
        let newState = processWithdraw(state, withdrawReq, sig, proof);

        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability)
    }

    @method swapTo(key: PrivateKey, req: Swap, sig: Signature, proof: LiabilityProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let totalLiability = this.totalLiability.get();
        this.totalLiability.assertEquals(totalLiability);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        sig.verify(req.account, req.toFields()).assertEquals(Bool(true));
        let depositReq = new Deposit({account: req.account, amount: req.toAmount, tid: req.toId, prev: req.prevTo});
        let state = new TreeState({root, totalLiability});
        let newState = processDeposit(state, depositReq, sig, proof);

        this.root.set(newState.root);
        this.totalLiability.set(newState.totalLiability)
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
    @method batch(key: PrivateKey, proof: RollupProof) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        proof.verify();

        this.root.assertEquals(proof.publicInput.root);
        this.root.set(proof.publicOutput.root);
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