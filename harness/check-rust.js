// Decrypts and verifies Rust-made output (crates/rg-notes/examples/emit_ciphertexts.rs)
// with the pinned TS engine: transact notes as receiver and sender, shield
// randoms, and EdDSA signatures. Exits non-zero on the first mismatch.
//
// Usage: node check-rust.js <rust-ciphertexts.json>

const fs = require('fs');
const path = require('path');

const resolveFrom = process.env.HARNESS_NODE_MODULES
  ? { paths: [process.env.HARNESS_NODE_MODULES] }
  : undefined;
const engineRoot = path.dirname(require.resolve('@railgun-community/engine', resolveFrom));
const eng = (rel) => require(path.join(engineRoot, rel));

const { deriveNodes, WalletNode } = eng('key-derivation/wallet-node');
const { initPoseidonPromise } = eng('utils/poseidon');
const { ByteUtils } = eng('utils/bytes');
const keys = eng('utils/keys-utils');
const { TransactNote } = eng('note/transact-note');
const { ShieldNote } = eng('note/shield-note');
const { TXIDVersion } = eng('models/poi-types');
const noteUtil = eng('note/note-util');

const assertEq = (a, b, what) => {
  if (a !== b) throw new Error(`${what}: TS ${a} != Rust ${b}`);
};

const walletOf = async ({ mnemonic, index }) => {
  const nodes = deriveNodes(mnemonic, index, '');
  const spending = nodes.spending.getSpendingKeyPair();
  const viewing = await nodes.viewing.getViewingKeyPair();
  const nk = await nodes.viewing.getNullifyingKey();
  return {
    viewing,
    address: {
      masterPublicKey: WalletNode.getMasterPublicKey(spending.pubkey, nk),
      viewingPublicKey: viewing.pubkey,
    },
  };
};

const main = async () => {
  await initPoseidonPromise;
  const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const tokenDataGetter = { getTokenDataFromHash: async (_v, _c, h) => noteUtil.getTokenDataERC20(h) };
  const chain = { type: 0, id: 11155111 };
  const bytes = ByteUtils.hexToBytes;

  for (const [i, n] of input.notes.entries()) {
    const sender = await walletOf(n.sender);
    const receiver = await walletOf(n.receiver);
    const noteCiphertext = {
      iv: n.ciphertext[0].slice(0, 32),
      tag: n.ciphertext[0].slice(32),
      data: n.ciphertext.slice(1),
    };
    for (const isSentNote of [false, true]) {
      const me = isSentNote ? sender : receiver;
      const sharedKey = await keys.getSharedSymmetricKey(
        me.viewing.privateKey,
        bytes(isSentNote ? n.blindedReceiverViewingKey : n.blindedSenderViewingKey),
      );
      const note = await TransactNote.decrypt(
        TXIDVersion.V2_PoseidonMerkle, chain, me.address, noteCiphertext, sharedKey, n.memo,
        n.annotationData, me.viewing.privateKey, bytes(n.blindedReceiverViewingKey),
        bytes(n.blindedSenderViewingKey), isSentNote, false, tokenDataGetter, undefined, undefined,
      );
      const what = `note ${i} ${isSentNote ? 'as sender' : 'as receiver'}`;
      assertEq(note.hash.toString(), n.commitment, `${what} commitment`);
      assertEq(note.value.toString(), n.value, `${what} value`);
      assertEq(note.memoText ?? null, n.memoText, `${what} memo`);
      assertEq(note.receiverAddressData.masterPublicKey, receiver.address.masterPublicKey, `${what} receiver MPK`);
      if (isSentNote) {
        assertEq(note.outputType, n.outputType, `${what} output type`);
        assertEq(note.walletSource, n.walletSource, `${what} wallet source`);
        assertEq(note.senderRandom, n.senderRandom, `${what} sender random`);
        assertEq(ByteUtils.hexlify(note.receiverAddressData.viewingPublicKey), ByteUtils.hexlify(receiver.viewing.pubkey), `${what} receiver VPK`);
      } else {
        const visible = n.senderRandom === '000000000000000000000000000000';
        assertEq(note.senderAddressData?.masterPublicKey, visible ? sender.address.masterPublicKey : undefined, `${what} sender MPK`);
      }
    }
  }

  for (const [i, s] of input.shields.entries()) {
    const receiver = await walletOf(s.receiver);
    const sharedKey = await keys.getSharedSymmetricKey(receiver.viewing.privateKey, bytes(s.shieldKey));
    assertEq(ShieldNote.decryptRandom(s.encryptedBundle, sharedKey), s.random, `shield ${i} random`);
  }

  for (const [i, s] of input.signatures.entries()) {
    const pub = keys.getPublicSpendingKey(bytes(s.privateKey));
    const sig = { R8: s.R8.map(BigInt), S: BigInt(s.S) };
    if (!keys.verifyEDDSA(BigInt(s.message), sig, pub)) throw new Error(`signature ${i} rejected`);
    const ts = keys.signEDDSA(bytes(s.privateKey), BigInt(s.message));
    assertEq(ts.S.toString(), s.S, `signature ${i} S`);
  }

  console.log(
    `ok: ${input.notes.length} notes decrypted both ways, ${input.shields.length} shields, ${input.signatures.length} signatures verified`,
  );
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
