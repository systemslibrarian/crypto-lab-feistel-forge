import { measureCell, mergeCells, type Cell, type Distinguisher, type Mode, type Transcript } from '../attacks/lubyRackoff';
import { toHex } from '../des/bytes';
import { append, button, card, clear, disclosure, el, intro, scroller, selectField, statusRegion, textField, verdict } from './dom';

export const ROUNDS_NEGATIVE_CLAIM='Zero measured advantage against D1–D3 does not make a Feistel network a pseudorandom permutation.';
const yieldFrame=()=>new Promise<void>(resolve=>setTimeout(resolve,0));
const ratio=(hits:number,trials:number)=>hits/trials;

export function renderRoundsPanel(root:HTMLElement):void {
  clear(root);
  append(root,intro('How many rounds look random?',
    el('p',{},'A Feistel network is always reversible, whatever its round function does. That does not make it look random. With good, independent round functions, one and two rounds give themselves away; three can fool an observer who can only encrypt. To also fool an observer who can decrypt, the construction needs four rounds.'),
    el('p',{},'Here “good” is an assumption about the functions, and “fool” is the theorem’s computational guarantee, not a verdict these few experiments can prove.')));
  let mode:Mode='random',epoch=0,busy=false,hasOutput=false,swap=false;
  const random=button('Random functions','seg-btn',{'aria-pressed':'true'}),des=button('DES functions','seg-btn',{'aria-pressed':'false'});
  const same=el('input',{type:'checkbox',id:'lr-same'}),focus=el('input',{type:'checkbox',id:'lr-focus'});
  const trials=textField('lr-trials','Trials per world, per cell','200','Whole numbers from 10 to 5,000. Runs yield between small batches; Cancel discards partial results.');trials.input.inputMode='numeric';
  const rounds=selectField('lr-rounds','Rounds for the stepper and focused view',[['1','1 round'],['2','2 rounds'],['3','3 rounds'],['4','4 rounds']],'3');
  const run=button('Run matrix','btn btn-primary',{id:'lr-run'}),cancel=button('Cancel','btn',{id:'lr-cancel'}),step=button('Step one trial','btn',{id:'lr-step'});
  cancel.disabled=true;
  const fixture=button('Try four rounds with one shared function','btn',{id:'lr-fixture'}),trySwap=button('Try the swap test','btn',{id:'lr-swap'});
  const state=statusRegion('Round-count experiment status');state.id='lr-state';
  const matrix=el('div',{id:'lr-matrix'}),trace=el('div',{id:'lr-transcript'}),negative=el('div',{id:'lr-negative'});
  append(root,card('Ask the same questions in two worlds','Every count comes from fresh browser trials.',
    el('div',{class:'lr-mode',role:'group','aria-label':'Round function'},random,des),
    el('p',{},'Random mode draws independent lazy 32-bit functions. DES mode uses the first four bytes of DES with a fresh key on R followed by four zero bytes. DES is a historical stand-in for a keyed pseudorandom function, with only a 56-bit key; these tests ask at most three oracle queries, not a key search.'),
    el('label',{class:'checkbox-line',for:'lr-same'},same,'Same function every round (deliberately broken)'),
    el('p',{class:'field-help'},'With one round, sharing changes nothing. DES keys get odd parity; weak and semi-weak keys are redrawn. Each trial starts over with fresh functions or keys.'),
    el('div',{class:'controls'},trials.wrap,rounds.wrap),
    el('label',{class:'checkbox-line',for:'lr-focus'},focus,'Show only the selected round in the matrix'),
    el('p',{id:'lr-convention'},'Convention: Lᵢ = Rᵢ₋₁; Rᵢ = Lᵢ₋₁ ⊕ fᵢ(Rᵢ₋₁). Output is (Lᵣ, Rᵣ), with no final swap. The DES exhibits keep their own swap.'),
    el('p',{},'A hit means the distinguisher guesses “Feistel”. We measure Pr[D=1 | Feistel] and Pr[D=1 | random permutation], then subtract the second from the first. Both worlds use the same enc/dec interface. A random world order is chosen outside the distinguisher for each paired trial.'),
    el('div',{class:'controls'},run,cancel,step),state,matrix,negative,
    el('div',{class:'controls'},fixture,trySwap),
    el('p',{},'D1: one encryption, test S = R. D2: two encryptions at the same R, test S ⊕ S′ = Δ. D3: those two encryptions and Dec(S′, T′ ⊕ Δ), test R″ = S ⊕ S′ ⊕ R. D-swap: two encryptions, test Enc(T,S) = (R,L).'),
    el('p',{title:'D2 and D3 need two different left halves.'},'Δ is redrawn until nonzero: L′ = L ⊕ Δ must differ from L.')));
  append(root,card('Step one D3 trial','Two encryptions and one inverse query; change the selected round count above.',trace));
  const weak=button('Open Same Circuit Both Ways');weak.addEventListener('click',()=>{const tab=document.querySelector<HTMLButtonElement>('#tab-circuit');tab?.click();tab?.focus();});
  append(root,disclosure('Why three rounds survive encryption queries',el('p',{},'With independent random functions, the first round masks a changed left half; the next new function input gives an unrelated output. Except when intermediate half-block inputs collide, forward-query transcripts can be coupled to those of a random permutation. The collision probability grows with the square of the query count divided by the half-domain size. Replacing the random functions by secure PRFs adds their distinguishing error. An inverse query changes this argument: D3 exposes a relation after three rounds, while four independent rounds support the strong-PRP theorem.')),
    disclosure('What this does not prove',el('p',{},ROUNDS_NEGATIVE_CLAIM),el('p',{},'Finite measurements of four particular rules are not a proof against all adversaries. Reusing one function breaks the independence assumption. The swap identity distinguishes that construction even when D1–D3 find no advantage. DES weak keys express the related symmetry in DES’s convention, where encryption becomes its own inverse.'),weak),
    el('p',{class:'lr-sources'},'Sources: ',el('a',{href:'https://epubs.siam.org/doi/10.1137/0217022'},'Luby–Rackoff (1988)'),'; Katz–Lindell, Introduction to Modern Cryptography, third edition, §8.6 and Exercises 8.16–8.18. The four rules are explicitly derived experiment relations, not quotations.'),
    el('p',{class:'lr-sources'},'Related experiments: ',el('a',{href:'https://systemslibrarian.github.io/crypto-lab-simon-period/'},'Simon Period: quantum queries'),'; ',el('a',{href:'https://systemslibrarian.github.io/crypto-lab-format-ward/'},'Format Ward: small half-domains'),'; ',el('a',{href:'https://systemslibrarian.github.io/crypto-lab-hidden-bit/'},'Hidden Bit: lazy oracle sampling'),'.'));

  const context=()=>JSON.stringify([mode,same.checked,rounds.select.value,trials.input.value,focus.checked]);let previous=context();
  const controls=(running:boolean)=>{busy=running;run.disabled=step.disabled=fixture.disabled=trySwap.disabled=running;cancel.disabled=!running;};
  function retire(message='Inputs changed — matrix and transcript are stale. Run again.'):void {
    epoch++;controls(false);clear(matrix);clear(trace);clear(negative);clear(state);if(hasOutput)append(state,verdict('info',message));hasOutput=false;
  }
  function changed():void{const next=context();if(next===previous)return;previous=next;retire();}
  same.addEventListener('change',changed);focus.addEventListener('change',changed);rounds.select.addEventListener('change',changed);trials.input.addEventListener('input',changed);
  function setMode(next:Mode):void{mode=next;random.setAttribute('aria-pressed',String(mode==='random'));des.setAttribute('aria-pressed',String(mode==='des'));changed();}
  random.addEventListener('click',()=>setMode('random'));des.addEventListener('click',()=>setMode('des'));
  cancel.addEventListener('click',()=>retire('Cancelled — partial results discarded.'));
  new MutationObserver(()=>{if(root.hidden&&busy)retire('Cancelled on leaving the tab — partial results discarded.');}).observe(root,{attributes:true,attributeFilter:['hidden']});
  function count():number{const value=Number(trials.input.value);if(!/^\d+$/.test(trials.input.value)||!Number.isInteger(value)||value<10||value>5000)throw new Error('Trials must be a whole number from 10 to 5,000.');return value;}
  function fail(error:unknown):void{retire();clear(state);append(state,verdict('fail',error instanceof Error?error.message:String(error)));}

  function renderCell(cell:Cell,r:number,d:Distinguisher):HTMLTableCellElement {
    const pf=ratio(cell.feistel.hits,cell.feistel.trials),pr=ratio(cell.random.hits,cell.random.trials),adv=pf-pr;
    const distinguished=Math.abs(adv)>0.05,tone=distinguished?'alarm':'info';
    return el('td',{'data-rounds':r,'data-d':d,'data-pf':pf,'data-pr':pr,'data-adv':adv},
      el('p',{'data-world':'feistel'},`Feistel: ${cell.feistel.hits}/${cell.feistel.trials} = ${pf.toFixed(6)}`),
      el('p',{'data-world':'random'},`Random permutation: ${cell.random.hits}/${cell.random.trials} = ${pr.toFixed(6)}`),
      el('p',{'data-advantage':'true'},`Advantage: ${adv.toFixed(6)}`),
      el('p',{class:'field-help'},`Each world: ${cell.feistel.encryptions} encryptions, ${cell.feistel.decryptions} inverse queries.`),
      verdict(tone,distinguished?'✕ distinguished':'– no advantage measured'));
  }
  function showTrace(t:Transcript,cell:Cell):void {
    clear(trace);trace.dataset.rounds=rounds.select.value;trace.dataset.mode=mode;
    append(trace,el('p',{},`Feistel world · ${rounds.select.value} rounds · ${mode==='des'?'DES functions':'random functions'} · ${same.checked?'shared':'independent'} functions · ${cell.redraws} weak-key redraws.`));
    const dl=el('dl',{class:'kv'});
    for(const [i,key] of cell.keys.entries())append(dl,el('dt',{},`Key ${i+1}`),el('dd',{'data-key':i+1,class:'hexline'},toHex(key)));
    for(const [name,value] of Object.entries(t.fields))append(dl,el('dt',{},name),el('dd',{'data-field':name,class:'hexline'},toHex(value)));
    append(trace,dl);
    const rows=el('tbody');for(let i=0;i<4;i++)append(rows,el('tr',{},el('th',{scope:'row'},`Byte ${i+1}`),el('td',{},t.fields.actual[i].toString(16).padStart(2,'0')),el('td',{},t.fields.expected[i].toString(16).padStart(2,'0')),el('td',{},t.fields.actual[i]===t.fields.expected[i]?'equal':'different')));
    append(trace,scroller('D3 byte comparison','lr-scroll',el('table',{},el('caption',{},'R″ compared with S ⊕ S′ ⊕ R'),el('thead',{},el('tr',{},el('th',{scope:'col'},'Byte'),el('th',{scope:'col'},'Actual'),el('th',{scope:'col'},'Expected'),el('th',{scope:'col'},'Relation'))),rows)),
      verdict(t.hit?'alarm':'info',t.hit?'✕ D3 distinguished this trial':'– D3 relation did not hold; no security conclusion.'),
      el('p',{},`Queries actually made: ${t.encryptions} encryptions, ${t.decryptions} decryption.`));
  }
  async function measure():Promise<void> {
    let n:number;try{n=count();}catch(error){fail(error);return;}
    retire();hasOutput=true;controls(true);const ticket=epoch,started=performance.now(),ds:Distinguisher[]=swap?['D1','D2','D3','D-swap']:['D1','D2','D3'];
    const rs=focus.checked?[Number(rounds.select.value)]:[1,2,3,4],cells=new Map<string,Cell>();
    try{
      for(const r of rs)for(const d of ds){
        let cell:Cell|undefined;
        for(let done=0;done<n;done+=10){
          if(ticket!==epoch)return;
          state.textContent=`Measuring ${r} rounds, ${d}: ${done}/${n} paired trials. No partial verdict is shown.`;
          await yieldFrame();if(ticket!==epoch)return;
          const part=measureCell(r,d,mode,Math.min(10,n-done),same.checked);cell=cell?mergeCells(cell,part):part;
        }
        cells.set(`${r}:${d}`,cell!);
      }
      if(ticket!==epoch)return;
      const body=el('tbody');for(const r of rs){const row=el('tr',{},el('th',{scope:'row'},`${r} ${r===1?'round':'rounds'}`));for(const d of ds)append(row,renderCell(cells.get(`${r}:${d}`)!,r,d));append(body,row);}
      append(matrix,scroller('Measured round-count matrix','lr-scroll',el('table',{},el('caption',{},`${focus.checked?'Focused view: selected round only.':'All four round counts.'} ${same.checked?'Same function every round.':'Independent functions.'} ${n} fresh trials per world in every cell.`),el('thead',{},el('tr',{},el('th',{scope:'col'},'Rounds'),...ds.map(d=>el('th',{scope:'col'},d)))),body)));
      const fourth=['D1','D2','D3'].map(d=>cells.get(`4:${d}`));
      if(same.checked&&fourth.every(c=>c&&Math.abs(c.feistel.hits/c.feistel.trials-c.random.hits/c.random.trials)<=.05)){
        append(negative,verdict('info','NO ADVANTAGE ON D1–D3 — AND NOT A PRP'),el('p',{'data-claim':'NEG-2'},ROUNDS_NEGATIVE_CLAIM),el('p',{},'This warning concerns the four-round row. The shared-function network obeys the swap identity; try its test to expose the missing distinction.'));
      }else append(negative,el('p',{},ROUNDS_NEGATIVE_CLAIM));
      clear(state);append(state,verdict('info',`Complete: ${rs.length*ds.length} measured cells in ${(performance.now()-started).toFixed(1)} ms. A difference at most 0.05 is labelled “no advantage measured”; that display threshold is not a proof.`));
    }catch(error){if(ticket===epoch)fail(error);}finally{if(ticket===epoch)controls(false);}
  }
  run.addEventListener('click',()=>{void measure();});
  step.addEventListener('click',()=>{try{count();const cell=measureCell(Number(rounds.select.value),'D3',mode,1,same.checked);showTrace(cell.lastFeistel,cell);hasOutput=true;}catch(error){fail(error);}});
  fixture.addEventListener('click',()=>{mode='random';random.setAttribute('aria-pressed','true');des.setAttribute('aria-pressed','false');same.checked=true;rounds.select.value='4';focus.checked=true;swap=false;changed();void measure();});
  trySwap.addEventListener('click',()=>{swap=true;void measure();});
}
