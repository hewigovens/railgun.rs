// Sign and send JSONL transactions ({label, to, value, data}) from a test EOA,
// waiting for each receipt. The key file is a 0x hex private key.
//
//   node harness/send.js new <key-file>            make a key, print its address
//   node harness/send.js send <rpc> <key-file> <txs.jsonl>
const fs = require('fs');
const path = require('path');
const modules = process.env.HARNESS_NODE_MODULES || path.join(__dirname, 'node_modules');
const { ethers } = require(path.join(modules, 'ethers'));

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (cmd === 'new') {
    const [file] = args;
    if (fs.existsSync(file)) throw new Error(`${file} exists; not overwriting`);
    const wallet = ethers.Wallet.createRandom();
    fs.writeFileSync(file, `${wallet.privateKey}\n`, { mode: 0o600 });
    console.log(wallet.address);
    return;
  }
  if (cmd !== 'send') throw new Error('usage: send.js new|send ...');
  const [rpc, keyFile, txFile] = args;
  const provider = new ethers.JsonRpcProvider(rpc);
  const wallet = new ethers.Wallet(fs.readFileSync(keyFile, 'utf8').trim(), provider);
  const txs = fs.readFileSync(txFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  for (const { label, to, value, data } of txs) {
    const sent = await wallet.sendTransaction({ to, value: BigInt(value), data });
    console.error(`${label}: ${sent.hash}`);
    const receipt = await sent.wait();
    if (receipt.status !== 1) throw new Error(`${label} reverted: ${sent.hash}`);
    console.error(`${label}: mined in block ${receipt.blockNumber}, gas ${receipt.gasUsed}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
