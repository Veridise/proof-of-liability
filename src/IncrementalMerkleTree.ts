import { Field, MerkleWitness, SmartContract, SelfProof, State, method, state, Reducer, Circuit, Provable, Struct, Poseidon, Bool, MerkleTree, Experimental, AccountUpdate } from "o1js";
import { Prover } from "o1js/dist/node/lib/proof_system";

export { RollupProver };

export class IncrementalWitness extends MerkleWitness(32) {}
export class MerkleProof extends Struct({witness: IncrementalWitness, leaf: Field}) {}
export class MerkleInfo extends Struct({isLeft: Provable.Array(Bool, 31), siblings: Provable.Array(Field, 31), root: Field, ind: Field}) {}

export class TreeAction extends Struct({leaf: Field}) {
    toFields(): Field[] {
        return [this.leaf]
    }
}
export class TreeState extends Struct({root: Field, actionsHash: Field, index: Field}) {}
export class TreeRollup extends Struct({from: TreeState, to: TreeState}) {}
export class Switcher extends Struct({oldNode:Field, newNode:Field}) {
    toFields(): Field[] {
        return [this.oldNode, this.newNode]
    }
}

const BATCH_SIZE = 32

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

function zero(i: number): Field {
    /*let zeros = [Field(0)];
    for (let i = 1; i < 32; i++) {
        zeros[i] = Poseidon.hash([zeros[i - 1], zeros[i - 1]]);
    }
    return zeros[i];*/

    // TODO: Ask if this is safe
    return zeros[i];
} 

function indexToPath(index: Field): Bool[] {
    let indices: Field[] = []
    let isLeft: Bool[] = []

    indices.push(index);
    for(let i = 0; i < 31; i++) {
        isLeft.push(indices[i].isEven().not())
        indices.push(indices[i].div(2))
    }

    return isLeft;
}

function advanceActionsHash(prevHash: Field, action: TreeAction): Field {
    const eventHash = AccountUpdate.Actions.hash([action.toFields()])
    return AccountUpdate.Actions.updateSequenceState(prevHash, eventHash)
}

function processLayer(curLayer: Field[], leftSibling: Field, rightSibiling: Field, isLeft: Bool, isOdd: Bool, size: number): Field[] {
    (size % 2 == 0) ? 0 : 1;
    if(size % 2 == 0) {

    }
}

//validate that new passed in tree is correct
let RollupProver = Experimental.ZkProgram({
    publicInput: TreeRollup,
    methods: {
        insert: {
            privateInputs: [Provable.Array(Field, 31), Provable.Array(Field, 31), TreeAction],

            // Note: This does not validate that everything to the left has remained the same and 
            //        everything to the right is empty in the new tree. We should do this at 
            //        verification time to allow proofs to be generated for different parts of the tree
            method(update: TreeRollup, oldSiblings: Field[], newSiblings: Field[], action: TreeAction) {
                let isLeft: Bool[] = indexToPath(update.from.index);
                let oldTree: Field[] = [zero(0)];
                let newTree: Field[] = [action.leaf];

                for(let i = 0; i < 31; i++) {
                    let treeNodes = new Switcher({oldNode: oldTree[i], newNode: newTree[i]})
                    let siblingNodes = new Switcher({oldNode: oldSiblings[i], newNode: newSiblings[i]})
                    let left = Provable.if(isLeft[i], treeNodes, siblingNodes)
                    let right = Provable.if(isLeft[i], siblingNodes, treeNodes)
                    oldTree[i + 1] = Poseidon.hash([left.oldNode, right.oldNode])
                    newTree[i + 1] = Poseidon.hash([left.newNode, right.newNode])
                }

                update.from.root.assertEquals(oldTree[31])
                update.to.root.assertEquals(newTree[31])
                update.from.index.add(Field(1)).assertEquals(update.to.index)
                update.to.actionsHash.assertEquals(advanceActionsHash(update.from.actionsHash, action))
            }
        },
        insertBatch: {
            privateInputs: [Provable.Array(Field, 31), Provable.Array(Field, 31), Provable.Array(Field, 31), Provable.Array(TreeAction, BATCH_SIZE)],

            // Note: This does not validate that everything to the left has remained the same and 
            //        everything to the right is empty in the new tree. We should do this at 
            //        verification time to allow proofs to be generated for different parts of the tree
            method(update: TreeRollup, oldSiblings: Field[], newLeftSiblings: Field[], newRightSiblings: Field[], actions: TreeAction[]) {
                let isLeft: Bool[] = indexToPath(update.from.index);
                let oldTree: Field[] = [zero(0)];
                let newTree: Field[] = [actions[0].leaf];

                // validate old root, inclusion of first action and initialize necessary structures
                for(let i = 0; i < 31; i++) {
                    let left = Provable.if(isLeft[i], oldTree[i], oldSiblings[i])
                    let right = Provable.if(isLeft[i], oldSiblings[i], oldTree[i])
                    oldTree[i + 1] = Poseidon.hash([left, right])
                }

                update.from.root.assertEquals(oldTree[31])
                update.from.index.add(Field(BATCH_SIZE)).assertEquals(update.to.index)
                update.to.actionsHash.assertEquals(actions.reduce((acc, cur) => advanceActionsHash(acc, cur), update.from.actionsHash))


                //let levels: Field[][] = new Array(32).fill([], 0, 32)
                //for(let i = 0; i < BATCH_SIZE; i++) {
                //    levels[0].push(actions[i].leaf)
                //}

                //Allocate tree structure
                
                let curLayer: Field[] = actions.map(a => a.leaf)
                let size = 32;
                //let layerOne: Field[] = processLayer(layerZero, newLeftSiblings[0], newRightSiblings[0], isLeft[0], 32)
                //processLayer(layerOne, newLeftSiblings[1], newRightSiblings[1], isLeft[1], 17)

                for(let i = 0; i < 31; i++) {
                    let nextLayer: Field[] = processLayer(curLayer, newLeftSiblings[0], newRightSiblings[0], isLeft[0], size)
                    curLayer = nextLayer;
                    size = size / 2 + 1
                }

                update.to.root.assertEquals(curLayer[0])

                //Extra level if:
                //  1. previous level is odd and level > 4
                //  2. previous level started on the right
                //                         e
                //                         d
                //             c                        c
                //             b                        b
                //       a           a           a           a
                //    z     z     z     z     z     z     z     z  
                //  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y
                // xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
                //               d                             d              
                //               c                             c
                //      b                 b                    b
                //      a           a           a           a     a   
                //   z     z     z     z     z     z     z     z  z
                // y  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y y
                // x xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx x
            }
        },
        merge: {
            privateInputs: [SelfProof, SelfProof],
            method(update: TreeRollup, left: SelfProof<TreeRollup, void>, right: SelfProof<TreeRollup, void>) {
                left.verify()
                right.verify()

                // connect left and right
                left.publicInput.to.index.assertEquals(right.publicInput.from.index);
                left.publicInput.to.actionsHash.assertEquals(right.publicInput.from.actionsHash);
                left.publicInput.from.root.assertEquals(right.publicInput.from.root)
                left.publicInput.to.root.assertEquals(right.publicInput.to.root)

                // Asserting updates
                update.from.actionsHash.assertEquals(left.publicInput.from.actionsHash)
                update.from.index.assertEquals(left.publicInput.from.index)
                update.from.root.assertEquals(left.publicInput.from.root)
                update.to.actionsHash.assertEquals(right.publicInput.to.actionsHash)
                update.to.index.assertEquals(right.publicInput.to.index)
                update.to.root.assertEquals(right.publicInput.to.root)
            }
        }
    }
});

export class IncrementalMerkleTree extends SmartContract {
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
    @state(Field) actionState = State<Field>();

    reducer = Reducer({actionType: TreeAction});

    init() {
        super.init();
        let zeroRoot = this.zero(31);
        this.root.set(zeroRoot);
        this.ind.set(Field(0));
        this.actionState.set(Reducer.initialActionState);
    }

    zero(i: number): Field {
        /*let zeros = [Field(0)];
        for (let i = 1; i < 32; i++) {
            zeros[i] = Poseidon.hash([zeros[i - 1], zeros[i - 1]]);
        }
        return zeros[i];*/

        // TODO: Ask if this is safe
        return this.zeros[i];
    }

    @method sync(witness: IncrementalWitness) {
        let root = this.root.get();
        this.root.assertEquals(root);

        let actionState = this.actionState.get();
        this.actionState.assertEquals(actionState);

        let ind = this.ind.get();
        this.ind.assertEquals(ind);

        witness.calculateIndex().assertEquals(ind);
        witness.calculateRoot(this.zero(0)).assertEquals(root);

        let info = new MerkleInfo({isLeft: witness.isLeft, siblings: witness.path, root: root, ind: ind});

        let pendingActions = this.reducer.getActions({fromActionState: actionState});
        let { state: updatedTree, actionState: newActionState } =
            this.reducer.reduce(
                pendingActions,
                MerkleInfo,
                (state: MerkleInfo, action: TreeAction) => {
                    let isLeft = [];
                    let siblings = [];
                    let nodes = [];

                    nodes.push(action.leaf);
                    isLeft.push(state.isLeft[0].not());
                    siblings.push(Provable.if(isLeft[0], this.zero(0), action.leaf));
                    for(let i = 1; i < 31; i++) {
                        //check to see if the previous level overflowed to a new left node
                        isLeft.push(Provable.if(isLeft[i - 1].and(state.isLeft[i - 1].not()), state.isLeft[i].not(), state.isLeft[i]));

                        //get hash of current node
                        const left: Field = Provable.if(state.isLeft[i - 1], nodes[i - 1], state.siblings[i - 1]);
                        const right: Field = Provable.if(state.isLeft[i - 1], state.siblings[i - 1], nodes[i - 1]);
                        nodes.push(Poseidon.hash([left, right]));

                        //if this is a left node, sibling is zero
                        // otherwise the sibling is the previous node if this is a new right node, or the sibling didn't change
                        siblings.push(Provable.if(isLeft[i], this.zero(i), Provable.if(state.isLeft[i], nodes[i], state.siblings[i])));
                    }

                    //get hash of current node
                    const left: Field = Provable.if(state.isLeft[30], nodes[30], state.siblings[30]);
                    const right: Field = Provable.if(state.isLeft[30], state.siblings[30], nodes[30]);
                    nodes.push(Poseidon.hash([left, right]));

                    return {isLeft: isLeft, siblings: siblings, root: nodes[31], ind: state.ind.add(Field(1))}
                },
                { state: info, actionState }
            );

        this.actionState.set(newActionState);
        this.root.set(updatedTree.root);
        this.ind.set(updatedTree.ind);
    }

    @method slowInsert(proof: MerkleProof) {
        //duplicated a bunch of update code because I just wanted to put this here for completeness reasons
        let root = this.root.get();
        this.root.assertEquals(root);

        let ind = this.ind.get();
        this.ind.assertEquals(ind);

        proof.witness.calculateIndex().assertEquals(ind);
        proof.witness.calculateRoot(this.zero(0)).assertEquals(root);

        const newRoot = proof.witness.calculateRoot(proof.leaf);
        this.root.set(newRoot);
        this.ind.set(ind.add(1));
    }

    @method insert(newLeaf: Field) {
        //note, this doesn't account for the size, need to see if we can see # dispatched
        this.reducer.dispatch(new TreeAction({leaf: newLeaf}));
    }

    @method remove(proof: MerkleProof) {
        this.update(proof, this.zero(0));
    }

    @method update(proof: MerkleProof, newLeaf: Field) {
        //problems with using dispatch method for update: this introduces a race condition that could possibly be exploited
        let root = this.root.get();
        this.root.assertEquals(root);

        let ind = this.ind.get();
        this.ind.assertEquals(ind);

        proof.witness.calculateIndex().assertLessThan(ind);
        proof.witness.calculateRoot(proof.leaf).assertEquals(root);

        const newRoot = proof.witness.calculateRoot(newLeaf);
        this.root.set(newRoot);
    }
}