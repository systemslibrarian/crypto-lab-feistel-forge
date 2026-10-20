// Mutations run only on a committed, clean source baseline. Each is built, killed,
// restored byte-for-byte, rebuilt and tested green before the next begins.
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'); process.chdir(root);
const config = process.env.PLAYWRIGHT_CONFIG;
const browser = title => ['npx', ['playwright','test','e2e/claims.spec.ts','--project=claims','--grep',title,'--workers=1','--retries=0',...(config ? ['--config',config] : [])]];
const unit = title => ['npx',['vitest','run','src/attacks/lubyRackoff.test.ts','-t',title]];
const build = ['npm',['run','build']];
const run = ([cmd,args]) => {
 const env={...process.env,CI:'1'};
 if(cmd==='npx'&&args[0]==='playwright')env.MUTATION_ASSETS=JSON.stringify(Object.fromEntries(readdirSync('dist/assets').filter(p=>p.endsWith('.js')).map(p=>[p,createHash('sha256').update(readFileSync(join('dist/assets',p))).digest('hex')])));
 return spawnSync(cmd,args,{cwd:root,encoding:'utf8',env});
};
const pass = (cmd,label) => { const r=run(cmd); if(r.status!==0) throw Error(`${label}\n${r.stdout}\n${r.stderr}`); return r; };
const hash = () => { const h=createHash('sha256'); const walk=d=>{for(const e of readdirSync(d,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const p=join(d,e.name); if(e.isDirectory())walk(p);else {h.update(p);h.update(readFileSync(p));}}};walk('dist');return h.digest('hex'); };
const cases = [
 ['D3 wrong input half','src/attacks/lubyRackoff.ts','expected=xorBytes(xorBytes(S,Sprime),R)','expected=xorBytes(xorBytes(S,Sprime),L)',unit('pins independently worked multiplication')],
 ['inverse wrong function input','src/attacks/lubyRackoff.ts','fs[i](left)','fs[i](right)',browser('rounds DES D3 transcript')],
 ['same function ignored','src/attacks/lubyRackoff.ts',
  'if(same)while(fs.length<rounds){fs.push(fs[0]);if(keys.length)keys.push(keys[0].slice());}',
  'if(same&&fs.length<rounds)return makeRoundFunctions(rounds,mode,false,rng);',browser('rounds negative fixture')],
 ["world labels swapped", "src/ui/roundsPanel.ts", "      el('p',{'data-world':'feistel'},`Feistel: ${cell.feistel.hits}/${cell.feistel.trials} = ${pf.toFixed(6)}`),\n      el('p',{'data-world':'random'},`Random permutation: ${cell.random.hits}/${cell.random.trials} = ${pr.toFixed(6)}`),\n", "      el('p',{'data-world':'feistel'},`Random permutation: ${cell.feistel.hits}/${cell.feistel.trials} = ${pf.toFixed(6)}`),\n      el('p',{'data-world':'random'},`Feistel: ${cell.random.hits}/${cell.random.trials} = ${pr.toFixed(6)}`),\n", browser('rounds matrix raw counts')],
 ['distinguished cell neutral','src/ui/roundsPanel.ts',"tone=distinguished?'alarm':'info'","tone=distinguished?'info':'info'",browser('rounds matrix raw counts')],
 ['D3 transcript alarm neutral','src/ui/roundsPanel.ts',"verdict(t.hit?'alarm':'info'","verdict(t.hit?'info':'info'",browser('rounds DES D3 transcript')],
 ['missing negative claim','src/ui/roundsPanel.ts',
  "export const ROUNDS_NEGATIVE_CLAIM='Zero measured advantage against D1–D3 does not make a Feistel network a pseudorandom permutation.';",
  "export const ROUNDS_NEGATIVE_CLAIM='';",browser('rounds negative fixture')],
];
const dirty=spawnSync('git',['diff','--exit-code','--',...new Set(cases.map(x=>x[1]))],{encoding:'utf8'});
if(dirty.status!==0)throw Error('Commit the source baseline before mutation checks.');
pass(build,'baseline build');const baseline=hash();const evidence=[];
mkdirSync('mutation-logs',{recursive:true});
for(const [name,file,before,after,command] of cases){
 pass(command,`${name}: baseline test`);
 const original=readFileSync(file,'utf8');if(original.split(before).length!==2)throw Error(`${name}: expected one mutation site`);
 let mutant;
 try{
  writeFileSync(file,original.replace(before,after));
  const diff=spawnSync('git',['diff','--',file],{encoding:'utf8'}).stdout;if(!diff.trim())throw Error(`${name}: empty diff`);
  pass(build,`${name}: mutant build`); mutant=hash();if(mutant===baseline)throw Error(`${name}: bundle did not move`);
  const r=run(command);writeFileSync(`mutation-logs/${name.replaceAll(' ','-')}.log`,r.stdout+r.stderr);
  if(r.status===0 || /MUTATION_ASSET_MISMATCH/.test(r.stdout+r.stderr) || !/expect\(|AssertionError|Error: expect/.test(r.stdout+r.stderr))throw Error(`${name}: no assertion kill\n${r.stdout}\n${r.stderr}`);
  evidence.push({name,sourceDiff:diff,baseline,mutant,namedTest:command[1].includes('--grep') ? command[1][command[1].indexOf('--grep')+1] : command[1].at(-1),assertionFailure:true,retries:0,servedAssetGuard:true});
 }finally{writeFileSync(file,original);pass(build,`${name}: restore build`);if(hash()!==baseline)throw Error(`${name}: restored hash differs`);pass(command,`${name}: restored test`);}
 evidence.at(-1).restoredGreen=true;console.log(`${name}: killed; exact artifact restored; owning test green`);
}
writeFileSync('mutation-evidence.json',JSON.stringify(evidence,null,2)+'\n');
