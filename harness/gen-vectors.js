// Golden-vector generator. Runs the pinned Railgun TS engine (9.6.0) on
// deterministic inputs and writes JSON the Rust tests diff against.
//
// Usage: node gen-vectors.js <out-dir>
// Set HARNESS_NODE_MODULES to use a node_modules outside this folder.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const resolveFrom = process.env.HARNESS_NODE_MODULES
  ? { paths: [process.env.HARNESS_NODE_MODULES] }
  : undefined;
const enginePkg = require.resolve('@railgun-community/engine', resolveFrom);
const engineRoot = path.dirname(enginePkg);
// The package only exports its index, so internal modules load by path.
const eng = (rel) => require(path.join(engineRoot, rel));
const circomlibjs = require(
  require.resolve('@railgun-community/circomlibjs', { paths: [engineRoot] }),
);

const { deriveNodes, WalletNode } = eng('key-derivation/wallet-node');
const { getMasterKeyFromSeed, childKeyDerivationHardened, getPathSegments } = eng(
  'key-derivation/bip32',
);
const { Mnemonic } = eng('key-derivation/bip39');
const { encodeAddress, decodeAddress } = eng('key-derivation/bech32');
const { poseidon, poseidonHex, initPoseidonPromise } = eng('utils/poseidon');
const { getPublicSpendingKey } = eng('utils/keys-utils');
const engineVersion = JSON.parse(
  fs.readFileSync(path.join(engineRoot, '..', 'package.json'), 'utf8'),
).version;

// Deterministic byte stream: sha256(seed || counter).
let counter = 0;
const SEED = 'railgun-rust-core-vectors-v1';
const randomBytes = (n) => {
  const out = [];
  while (out.length < n) {
    const h = crypto.createHash('sha256').update(`${SEED}:${counter}`).digest();
    counter += 1;
    out.push(...h);
  }
  return Buffer.from(out.slice(0, n));
};
const hex = (b) => Buffer.from(b).toString('hex');
const big = (n) => n.toString(10);

const MNEMONICS = [
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  'test test test test test test test test test test test junk',
  'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote',
];
for (let i = 0; i < 4; i += 1) MNEMONICS.push(Mnemonic.fromEntropy(hex(randomBytes(16))));
for (let i = 0; i < 2; i += 1) MNEMONICS.push(Mnemonic.fromEntropy(hex(randomBytes(32))));

const CHAINS = [
  null, // all chains
  { type: 0, id: 1 },
  { type: 0, id: 56 },
  { type: 0, id: 137 },
  { type: 0, id: 42161 },
  { type: 0, id: 11155111 },
  { type: 1, id: 5 },
];

const keyVectors = async () => {
  const wallets = [];
  for (const mnemonic of MNEMONICS) {
    for (const password of ['', 'hunter2']) {
      for (const index of [0, 1, 7]) {
        const nodes = deriveNodes(mnemonic, index, password);
        const spending = nodes.spending.getSpendingKeyPair();
        const viewing = await nodes.viewing.getViewingKeyPair();
        const nullifyingKey = await nodes.viewing.getNullifyingKey();
        const masterPublicKey = WalletNode.getMasterPublicKey(spending.pubkey, nullifyingKey);
        const addresses = CHAINS.map((chain) => {
          const address = encodeAddress({
            masterPublicKey,
            viewingPublicKey: viewing.pubkey,
            chain: chain ?? undefined,
          });
          const decoded = decodeAddress(address);
          if (decoded.masterPublicKey !== masterPublicKey) throw new Error('decode mismatch');
          return { chain, address };
        });
        wallets.push({
          mnemonic,
          password,
          index,
          seed: Mnemonic.toSeed(mnemonic, password),
          spendingPrivateKey: hex(spending.privateKey),
          spendingPublicKey: spending.pubkey.map(big),
          viewingPrivateKey: hex(viewing.privateKey),
          viewingPublicKey: hex(viewing.pubkey),
          nullifyingKey: big(nullifyingKey),
          masterPublicKey: big(masterPublicKey),
          addresses,
        });
      }
    }
  }
  return wallets;
};

const bip32Vectors = () => {
  const out = [];
  const seed = Mnemonic.toSeed(MNEMONICS[0]);
  const master = getMasterKeyFromSeed(seed);
  for (const p of ["m/0'", "m/0'/1'", "m/44'/1984'/0'/0'/0'", "m/420'/1984'/0'/0'/3'", "m/2147483647'"]) {
    const node = getPathSegments(p).reduce((n, s) => childKeyDerivationHardened(n, s), master);
    out.push({ seed, path: p, chainKey: node.chainKey, chainCode: node.chainCode });
  }
  return { master: { seed, chainKey: master.chainKey, chainCode: master.chainCode }, paths: out };
};

const babyjubjubVectors = () => {
  const out = [];
  for (let i = 0; i < 16; i += 1) {
    const prv = randomBytes(32);
    const pub = getPublicSpendingKey(prv);
    const packed = circomlibjs.babyjub.packPoint(pub);
    out.push({ privateKey: hex(prv), publicKey: pub.map(big), packed: hex(packed) });
  }
  return out;
};

const poseidonVectors = () => {
  const out = [];
  const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  for (let width = 1; width <= 16; width += 1) {
    for (let k = 0; k < 3; k += 1) {
      // k = 2 uses full 256-bit inputs to cover reduction mod p.
      const inputs = Array.from({ length: width }, () => {
        const v = BigInt(`0x${hex(randomBytes(32))}`);
        return k === 2 ? v : v % p;
      });
      const wasm = poseidon(inputs);
      const js = circomlibjs.poseidon(inputs);
      if (wasm !== js) throw new Error(`poseidon wasm/js mismatch at width ${width}`);
      const viaHex = poseidonHex(inputs.map((x) => x.toString(16).padStart(64, '0')));
      if (BigInt(`0x${viaHex}`) !== wasm) throw new Error('poseidonHex mismatch');
      out.push({ inputs: inputs.map(big), output: big(wasm) });
    }
  }
  return out;
};

const main = async () => {
  const outDir = process.argv[2] ?? path.join(__dirname, '..', 'vectors');
  await initPoseidonPromise;
  const meta = { generator: 'harness/gen-vectors.js', engineVersion, seed: SEED };
  const files = {
    'bip32.json': bip32Vectors(),
    'babyjubjub.json': babyjubjubVectors(),
    'poseidon.json': poseidonVectors(),
    'keys.json': await keyVectors(),
  };
  Object.assign(files, await require('./notes-vectors')(eng, circomlibjs, files['keys.json']));
  fs.mkdirSync(outDir, { recursive: true });
  for (const [name, data] of Object.entries(files)) {
    fs.writeFileSync(path.join(outDir, name), `${JSON.stringify({ meta, data }, null, 2)}\n`);
    console.log(`wrote ${name}`);
  }
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
