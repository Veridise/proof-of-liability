import { Field, MerkleWitness, Mina, Poseidon, PrivateKey, PublicKey, Reducer, Signature, SmartContract, State, Struct, Token, TokenSymbol, UInt64, method, state } from "o1js";

const height = 32;
export class EscrowWitness extends MerkleWitness(height) {}

export class EscrowLeaf extends Struct({account: PublicKey, amount: UInt64}) {
    toFields(): Field[] {
        return this.amount.toFields().concat(this.account.toFields());
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

/*export class Deposit extends Struct({amount: Field, account: PublicKey}) {
    toFields(): Field[] {
        return [this.amount].concat(this.account.toFields);
    }
}

export class Withdraw extends Struct({amount: Field, account: PublicKey}) {

}*/

export class Escrow extends SmartContract {
    zeros = [
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

    @state(Field) root = State<Field>();
    @state(Field) ind = State<Field>();
    @state(Field) tid = State<Field>();
    @state(UInt64) curBal = State<UInt64>();
    @state(PublicKey) exchange = State<PublicKey>();

    reducer = Reducer({actionType: Field});

    zero(i: number): Field {
        return this.zeros[i];
    }

    init() {
        super.init();
        let zeroRoot = this.zero(31);
        this.root.set(zeroRoot);
        this.ind.set(Field(0));
        this.curBal.set(UInt64.from(0));
    }

    @method deposit(account: PublicKey, amount: UInt64, witness: EscrowWitness) {
        let tid = this.tid.get();
        this.tid.assertEquals(tid);

        let root = this.root.get();
        this.root.assertEquals(root);

        let ind = this.ind.get();
        this.ind.assertEquals(ind);

        let oldBal = this.curBal.get();
        this.curBal.assertEquals(oldBal);

        let curBal = Mina.getBalance(this.address, tid);
        curBal.assertGreaterThanOrEqual(oldBal.add(amount));

        witness.calculateIndex().assertEquals(ind);
        witness.calculateRoot(this.zero(0)).assertEquals(root);

        let leaf = new EscrowLeaf({account: account, amount: amount});
        let newRoot = witness.calculateRoot(leaf.hash());

        this.root.set(newRoot);
        this.ind.set(ind.add(1));
        this.curBal.set(curBal);
    }

    @method collect(key: PrivateKey, leaf: EscrowLeaf, witness: EscrowWitness) {
        let exchange = this.exchange.get();
        this.exchange.assertEquals(exchange);
        key.toPublicKey().assertEquals(exchange);

        let tid = this.tid.get();
        this.tid.assertEquals(tid);

        let root = this.root.get();
        this.root.assertEquals(root);

        let ind = this.ind.get();
        this.ind.assertEquals(ind);

        let oldBal = this.curBal.get();
        this.curBal.assertEquals(oldBal);

        this.account.balance.get();
        let curBal = Mina.getBalance(this.address, tid);
        curBal.assertGreaterThanOrEqual(oldBal);

        witness.calculateIndex().assertLessThanOrEqual(ind);
        witness.calculateRoot(leaf.hash()).assertEquals(root);

        let newLeaf = new EscrowLeaf({account: leaf.account, amount: UInt64.from(0)});
        let newRoot = witness.calculateRoot(newLeaf.hash());

        this.root.set(newRoot);
        this.curBal.set(curBal);
    }

    @method issueWithdraw() {

    }

    @method issueCollect() {

    }
}