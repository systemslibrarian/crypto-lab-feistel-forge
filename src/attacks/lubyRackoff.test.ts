import { describe, expect, it, vi } from 'vitest';
import * as des from '../des/des';
import { randomBytes, toHex } from '../des/bytes';
import { LazyRandomFunction32, LazyRandomPermutation64, desPrf, distinguish, feistelOracle, makeRoundFunctions, measureCell, type Mode, type RoundFunction } from './lubyRackoff';

const bytes=(hex:string)=>Uint8Array.from(hex.match(/../g)!.map(x=>parseInt(x,16)));
const word=(n:number)=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n);return b;};
const multiply=(c:number):RoundFunction=>x=>word(Math.imul(new DataView(x.buffer,x.byteOffset,4).getUint32(0),c));
const fixed={L:bytes('12345678'),R:bytes('9abcdef0'),delta:bytes('10203040')};

describe('Luby–Rackoff measured experiments',()=>{
  it('round trips in both directions for every round count and both function modes',()=>{
    for(const mode of ['random','des'] as Mode[])for(let rounds=1;rounds<=4;rounds++)for(let i=0;i<50;i++){
      const o=feistelOracle(makeRoundFunctions(rounds,mode,false).fs),x=randomBytes(8),y=randomBytes(8);
      expect(o.dec(o.enc(x))).toEqual(x);expect(o.enc(o.dec(y))).toEqual(y);
    }
  });
  it('pins independently worked multiplication examples for D1 D2 D3 and swap',()=>{
    const d1=distinguish(feistelOracle([multiply(3)]),'D1',fixed);
    expect(toHex(d1.fields.S)).toBe('9abcdef0');expect(d1.hit).toBe(true);
    const d2=distinguish(feistelOracle([multiply(3),multiply(5)]),'D2',fixed);
    expect(toHex(d2.fields.actual)).toBe('10203040');expect(d2.hit).toBe(true);
    const d3=distinguish(feistelOracle([multiply(3),multiply(5),multiply(7)]),'D3',fixed);
    // Concrete values calculated with unsigned 32-bit multiplication and XOR,
    // independently of the Feistel module; no expected value calls its helpers.
    expect(Object.fromEntries(Object.entries(d3.fields).map(([k,v])=>[k,toHex(v)]))).toMatchObject({
      S:'50b12bb8',T:'f6daf8a0',Sprime:'80123878',Tprime:'525d71a0',
      Ldouble:'1c5dad38',Rdouble:'4a1fcd30',actual:'4a1fcd30',expected:'4a1fcd30',
    });
    expect(d3.hit).toBe(true);expect([d3.encryptions,d3.decryptions]).toEqual([2,1]);
    const swap=distinguish(feistelOracle(Array(4).fill(multiply(3))),'D-swap',fixed);
    expect(toHex(swap.fields.swapOutput)).toBe('9abcdef012345678');expect(swap.hit).toBe(true);
  });
  it('measures every matrix cell and random-world hit rate from 200 fresh paired trials',()=>{
    const certain=[['D1','D3','D-swap'],['D2','D3'],['D3'],[]];
    // Outside the algebraic identities, accidental equalities have probability
    // about 2^-32 per trial (or less). Allowing 10/200 is deliberately loose:
    // under independent trials, binomial P(X>=11) is below 10^-85.
    for(let rounds=1;rounds<=4;rounds++)for(const d of ['D1','D2','D3','D-swap'] as const){
      const c=measureCell(rounds,d,'random',200);
      expect(c.feistel.trials).toBe(200);expect(c.random.trials).toBe(200);
      if(certain[rounds-1].includes(d))expect(c.feistel.hits).toBe(200);else expect(c.feistel.hits).toBeLessThanOrEqual(10);
      expect(c.random.hits).toBeLessThanOrEqual(10);
    }
    expect(measureCell(4,'D-swap','random',200,true).feistel.hits).toBe(200);
    for(const d of ['D1','D2','D3'] as const)expect(measureCell(4,d,'random',200,true).feistel.hits).toBeLessThanOrEqual(10);
  });
  it('keeps 10000 forward and unseen inverse queries bijective and isolated from caller mutation',()=>{
    const o=new LazyRandomPermutation64(),outputs=new Set<string>();
    for(let i=0;i<10000;i++){
      const x=new Uint8Array(8);new DataView(x.buffer).setUint32(4,i);
      const y=o.enc(x);outputs.add(toHex(y));expect(o.dec(y)).toEqual(x);
      const unseen=randomBytes(8),back=o.dec(unseen);expect(o.enc(back)).toEqual(unseen);
    }
    expect(outputs.size).toBe(10000);expect(o.size).toBe(20000);
    const x=bytes('0000000000000000'),y=o.enc(x),before=y.slice();y.fill(0);expect(o.enc(x)).toEqual(before);
  });
  it('lazy functions remain consistent and independent with no exposed writable maps',()=>{
    const f=new LazyRandomFunction32(),x=word(1),y=f.query(x),saved=y.slice();y.fill(0);
    expect(f.query(x)).toEqual(saved);expect(f.size).toBe(1);f.query(word(2));expect(f.size).toBe(2);
  });
  it('DES PRF calls the original CAVP-pinned encryptBlock and redraws a weak key',()=>{
    const key=bytes('133457799bbcdff1'),r=bytes('01234567');
    const expected=des.encryptBlock(key,bytes('0123456700000000')).slice(0,4),spy=vi.spyOn(des,'encryptBlock');
    expect(desPrf(key)(r)).toEqual(expected);expect(spy).toHaveBeenCalledWith(key,bytes('0123456700000000'));spy.mockRestore();
    let calls=0;const made=makeRoundFunctions(3,'des',true,()=>++calls===1?new Uint8Array(8):key);
    expect(made.redraws).toBe(1);expect(made.keys.map(toHex)).toEqual(Array(3).fill(toHex(key)));
    expect(made.fs[0]).toBe(made.fs[2]);
  });
  it('rejects malformed inputs and exhausted entropy without inventing a result',()=>{
    expect(()=>measureCell(0,'D1','random',10)).toThrow('Rounds');expect(()=>measureCell(4,'D3','random',0)).toThrow('batch');
    expect(()=>distinguish(feistelOracle([multiply(3)]),'D3',{...fixed,delta:word(0)})).toThrow('nonzero');
    const o=new LazyRandomPermutation64(n=>new Uint8Array(n));o.enc(new Uint8Array(8));
    expect(()=>o.enc(bytes('0000000000000001'))).toThrow('retry');
  });
});
