import { randomBytes, toHex, xorBytes } from '../des/bytes';
import { encryptBlock } from '../des/des';
import { runFeistel, type FeistelRoundFunction } from '../des/feistel';
import { fixParity, inspectKey } from '../des/weakKeys';

export type ByteSource=(length:number)=>Uint8Array;
export type RoundFunction=(half:Uint8Array)=>Uint8Array;
export interface Oracle {enc:(block:Uint8Array)=>Uint8Array;dec:(block:Uint8Array)=>Uint8Array}
export type Mode='random'|'des';
export type Distinguisher='D1'|'D2'|'D3'|'D-swap';
export const DISTINGUISHERS:Distinguisher[]=['D1','D2','D3','D-swap'];
const equal=(a:Uint8Array,b:Uint8Array):boolean=>a.length===b.length&&a.every((x,i)=>x===b[i]);
const join=(a:Uint8Array,b:Uint8Array):Uint8Array=>{const out=new Uint8Array(a.length+b.length);out.set(a);out.set(b,a.length);return out;};
function draw(n:number,rng:ByteSource):Uint8Array {const out=rng(n);if(out.length!==n)throw new Error('RNG returned the wrong number of bytes');return out;}
function check(block:Uint8Array,n:number):void{if(block.length!==n)throw new Error(`Expected ${n} bytes`);}

/** Hidden Bit's lazy-map pattern, extended to the full 32-bit half domain. */
export class LazyRandomFunction32 {
  readonly #table=new Map<string,Uint8Array>();
  constructor(private readonly rng:ByteSource=randomBytes){}
  query(input:Uint8Array):Uint8Array {
    check(input,4);const key=toHex(input);
    if(!this.#table.has(key))this.#table.set(key,draw(4,this.rng).slice());
    return this.#table.get(key)!.slice();
  }
  get size():number{return this.#table.size;}
}
/** Both directions lazily sample without replacement, including unseen inverse queries. */
export class LazyRandomPermutation64 implements Oracle {
  readonly #forward=new Map<string,Uint8Array>();readonly #backward=new Map<string,Uint8Array>();
  constructor(private readonly rng:ByteSource=randomBytes){}
  private query(input:Uint8Array,inverse:boolean):Uint8Array {
    check(input,8);const from=inverse?this.#backward:this.#forward,to=inverse?this.#forward:this.#backward,key=toHex(input);
    const known=from.get(key);if(known)return known.slice();
    for(let tries=0;tries<100000;tries++){
      const output=draw(8,this.rng),other=toHex(output);if(to.has(other))continue;
      from.set(key,output.slice());to.set(other,input.slice());return output.slice();
    }
    throw new Error('Permutation sampler exhausted its collision retry budget');
  }
  enc=(block:Uint8Array):Uint8Array=>this.query(block,false);
  dec=(block:Uint8Array):Uint8Array=>this.query(block,true);
  get size():number{return this.#forward.size;}
}
/** Same DES block implementation pinned by the existing CAVP suite. */
export function desPrf(key:Uint8Array):RoundFunction {
  check(key,8);const fixed=key.slice();
  return right=>{check(right,4);return encryptBlock(fixed,join(right,new Uint8Array(4))).slice(0,4);};
}
export function feistelInverse(block:Uint8Array,fs:RoundFunction[]):Uint8Array {
  check(block,8);let left:Uint8Array=block.slice(0,4),right:Uint8Array=block.slice(4);
  for(let i=fs.length-1;i>=0;i--){const previousLeft=xorBytes(right,fs[i](left));right=left;left=previousLeft;}
  return join(left,right);
}
export function feistelOracle(fs:RoundFunction[]):Oracle {
  if(!fs.length)throw new Error('At least one round is required');
  const subkeys=fs.map((_,i)=>{const key=new Uint8Array(6);key[0]=i;return key;});
  const f:FeistelRoundFunction={id:'luby-rackoff',name:'Independent round functions',note:'No final swap',isDes:false,apply:(right,key)=>fs[key[0]](right)};
  return {enc:block=>runFeistel(block,subkeys,f,false).output,dec:block=>feistelInverse(block,fs)};
}
export function makeRoundFunctions(rounds:number,mode:Mode,same:boolean,rng:ByteSource=randomBytes):{fs:RoundFunction[];keys:Uint8Array[];redraws:number} {
  if(!Number.isInteger(rounds)||rounds<1||rounds>4)throw new Error('Rounds must be 1–4');
  const fs:RoundFunction[]=[],keys:Uint8Array[]=[];let redraws=0;
  for(let i=0;i<(same?1:rounds);i++){
    if(mode==='random'){const lazy=new LazyRandomFunction32(rng);fs.push(right=>lazy.query(right));}
    else if(mode==='des'){
      let key:Uint8Array;
      for(;;){key=fixParity(draw(8,rng));if(inspectKey(key).keyClass==='ok')break;if(++redraws>=10000)throw new Error('DES key redraw budget exhausted');}
      keys.push(key);fs.push(desPrf(key));
    }else throw new Error('Unknown round-function mode');
  }
  if(same)while(fs.length<rounds){fs.push(fs[0]);if(keys.length)keys.push(keys[0].slice());}
  return {fs,keys,redraws};
}
export interface Challenge {L:Uint8Array;R:Uint8Array;delta:Uint8Array}
export interface Transcript {distinguisher:Distinguisher;fields:Record<string,Uint8Array>;hit:boolean;encryptions:number;decryptions:number}
export function challenge(rng:ByteSource=randomBytes):Challenge {
  const L=draw(4,rng),R=draw(4,rng);
  for(let i=0;i<10000;i++){const delta=draw(4,rng);if(delta.some(x=>x!==0))return {L,R,delta};}
  throw new Error('Nonzero delta retry budget exhausted');
}
/** Only this interface crosses into the adversary; there is no world flag here. */
export function distinguish(oracle:Oracle,d:Distinguisher,input:Challenge):Transcript {
  const {L,R,delta}=input;check(L,4);check(R,4);check(delta,4);
  if(!delta.some(x=>x!==0))throw new Error('D2 and D3 need two different left halves: delta must be nonzero');
  let encryptions=0,decryptions=0;
  const enc=(x:Uint8Array):Uint8Array=>{encryptions++;return oracle.enc(x);};
  const dec=(x:Uint8Array):Uint8Array=>{decryptions++;return oracle.dec(x);};
  const first=enc(join(L,R)),S=first.slice(0,4),T=first.slice(4),fields:Record<string,Uint8Array>={L,R,delta,S,T};
  let actual:Uint8Array,expected:Uint8Array;
  if(d==='D1'){actual=S;expected=R;}
  else if(d==='D-swap'){
    const second=enc(join(T,S));fields.swapOutput=second;actual=second;expected=join(R,L);
  }else{
    const Lprime=xorBytes(L,delta),second=enc(join(Lprime,R)),Sprime=second.slice(0,4),Tprime=second.slice(4);
    Object.assign(fields,{Lprime,Sprime,Tprime});
    if(d==='D2'){actual=xorBytes(S,Sprime);expected=delta;}
    else if(d==='D3'){
      const inverseInput=join(Sprime,xorBytes(Tprime,delta)),back=dec(inverseInput),Ldouble=back.slice(0,4),Rdouble=back.slice(4);
      Object.assign(fields,{inverseInput,Ldouble,Rdouble});actual=Rdouble;expected=xorBytes(xorBytes(S,Sprime),R);
    }else throw new Error('Unknown distinguisher');
  }
  fields.actual=actual;fields.expected=expected;
  return {distinguisher:d,fields,hit:equal(actual,expected),encryptions,decryptions};
}
export interface WorldCounts {hits:number;trials:number;encryptions:number;decryptions:number}
export interface Cell {feistel:WorldCounts;random:WorldCounts;lastFeistel:Transcript;lastRandom:Transcript;keys:Uint8Array[];redraws:number}
const empty=():WorldCounts=>({hits:0,trials:0,encryptions:0,decryptions:0});
// [extension] point: narrower halves need the variable split already noted in
// des/feistel.ts. At 32 bits, the theorem's birthday collisions are out of reach here.
export function measureCell(rounds:number,d:Distinguisher,mode:Mode,trials:number,same=false,rng:ByteSource=randomBytes):Cell {
  if(!Number.isInteger(trials)||trials<1||trials>5000)throw new Error('Internal trial batch must be 1–5000');
  const counts=[empty(),empty()];let lastFeistel!:Transcript,lastRandom!:Transcript,keys:Uint8Array[]=[],redraws=0;
  for(let i=0;i<trials;i++){
    // A random world order is chosen outside the distinguisher. Each paired
    // experiment supplies one fresh oracle from each world, so both get N trials.
    const first=draw(1,rng)[0]&1;
    for(const world of [first,first^1]){
      const functions=world===0?makeRoundFunctions(rounds,mode,same,rng):null;
      const oracle:Oracle=functions?feistelOracle(functions.fs):new LazyRandomPermutation64(rng);
      const transcript=distinguish(oracle,d,challenge(rng)),count=counts[world];
      count.hits+=Number(transcript.hit);count.trials++;count.encryptions+=transcript.encryptions;count.decryptions+=transcript.decryptions;
      if(functions){lastFeistel=transcript;keys=functions.keys;redraws+=functions.redraws;}else lastRandom=transcript;
    }
  }
  return {feistel:counts[0],random:counts[1],lastFeistel,lastRandom,keys,redraws};
}
export function mergeCells(a:Cell,b:Cell):Cell {
  const sum=(x:WorldCounts,y:WorldCounts):WorldCounts=>({hits:x.hits+y.hits,trials:x.trials+y.trials,encryptions:x.encryptions+y.encryptions,decryptions:x.decryptions+y.decryptions});
  return {...b,feistel:sum(a.feistel,b.feistel),random:sum(a.random,b.random),redraws:a.redraws+b.redraws};
}
