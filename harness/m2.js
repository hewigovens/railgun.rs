// M2 vectors: EdDSA Poseidon, Ed25519 shared keys and blinding, token hashes,
// commitments, nullifiers, V2 transact note ciphertexts and shield ciphertexts.
// Every random value the engine draws (IVs, note and sender randoms) comes from
// a queue this file fills, so each vector records the exact inputs it used.

const crypto = require('crypto');

module.exports = async (eng, circomlibjs, wallets) => {
  // A stream separate from M0/M1, so adding vectors here never shifts those.
  let counter = 0;
  const SEED = 'railgun-rust-core-vectors-m2-v1';
  const randomBytes = (n) => {
    const out = [];
    while (out.length < n) {
      out.push(...crypto.createHash('sha256').update(`${SEED}:${counter}`).digest());
      counter += 1;
    }
    return Buffer.from(out.slice(0, n));
  };
  const hex = (b) => Buffer.from(b).toString('hex');
  const big = (n) => n.toString(10);
  const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const randField = () => BigInt(`0x${hex(randomBytes(32))}`) % P;

  const { ByteUtils } = eng('utils/bytes');
  const queue = [];
  ByteUtils.randomHex = (length = 32) => {
    if (!queue.length) throw new Error(`unexpected randomHex(${length})`);
    const next = queue.shift();
    if (next.length !== length * 2) throw new Error(`randomHex(${length}) got ${next}`);
    return next;
  };
  const expectQueueEmpty = () => {
    if (queue.length) throw new Error(`unused randoms: ${queue}`);
  };

  const keys = eng('utils/keys-utils');
  const { TransactNote } = eng('note/transact-note');
  const { ShieldNoteERC20 } = eng('note/erc20/shield-note-erc20');
  const { ShieldNote } = eng('note/shield-note');
  const { Memo } = eng('note/memo');
  const noteUtil = eng('note/note-util');
  const { TXIDVersion } = eng('models/poi-types');
  const { TokenType, OutputType } = eng('models/formatted-types');
  const { MEMO_SENDER_RANDOM_NULL } = eng('models/transaction-constants');
  const WalletInfo = eng('wallet/wallet-info').default;

  // EdDSA over BabyJubJub with Poseidon.
  const eddsa = [];
  for (let i = 0; i < 16; i += 1) {
    const prv = randomBytes(32);
    const msg = randField();
    const sig = keys.signEDDSA(prv, msg);
    const pub = keys.getPublicSpendingKey(prv);
    if (!keys.verifyEDDSA(msg, sig, pub)) throw new Error('eddsa verify');
    if (keys.verifyEDDSA(msg + 1n, sig, pub)) throw new Error('eddsa verify tampered');
    eddsa.push({
      privateKey: hex(prv),
      message: big(msg),
      publicKey: pub.map(big),
      signature: { R8: sig.R8.map(big), S: big(sig.S) },
    });
  }

  // Ed25519: private scalars, shared keys, blinding.
  const scalars = [];
  for (let i = 0; i < 8; i += 1) {
    const prv = randomBytes(32);
    scalars.push({ privateKey: hex(prv), scalar: big(await keys.getPrivateScalarFromPrivateKey(prv)) });
  }
  const blinding = [];
  for (let i = 0; i < 12; i += 1) {
    const senderPriv = randomBytes(32);
    const receiverPriv = randomBytes(32);
    const senderPub = await keys.getPublicViewingKey(senderPriv);
    const receiverPub = await keys.getPublicViewingKey(receiverPriv);
    const random = hex(randomBytes(16));
    const senderRandom = i % 3 === 0 ? MEMO_SENDER_RANDOM_NULL : hex(randomBytes(15));
    const b = keys.getNoteBlindingKeys(senderPub, receiverPub, random, senderRandom);
    const senderShared = await keys.getSharedSymmetricKey(senderPriv, b.blindedReceiverViewingKey);
    const receiverShared = await keys.getSharedSymmetricKey(receiverPriv, b.blindedSenderViewingKey);
    if (hex(senderShared) !== hex(receiverShared)) throw new Error('shared key mismatch');
    const unblindedSender = keys.unblindNoteKey(b.blindedSenderViewingKey, random, senderRandom);
    const unblindedReceiver = keys.unblindNoteKey(b.blindedReceiverViewingKey, random, senderRandom);
    if (hex(unblindedSender) !== hex(senderPub)) throw new Error('unblind sender');
    if (hex(unblindedReceiver) !== hex(receiverPub)) throw new Error('unblind receiver');
    blinding.push({
      senderViewingPrivateKey: hex(senderPriv),
      senderViewingPublicKey: hex(senderPub),
      receiverViewingPrivateKey: hex(receiverPriv),
      receiverViewingPublicKey: hex(receiverPub),
      random,
      senderRandom,
      blindedSenderViewingKey: hex(b.blindedSenderViewingKey),
      blindedReceiverViewingKey: hex(b.blindedReceiverViewingKey),
      sharedKey: hex(senderShared),
    });
  }
  // A y coordinate with no point on the curve: the engine returns undefined.
  const notAPoint = (() => {
    for (let y = 2; ; y += 1) {
      const enc = Buffer.alloc(32);
      enc.writeUInt32LE(y, 0);
      try {
        eng('utils/scalar-multiply').scalarMultiplyJavascript(enc, 5n);
      } catch {
        return enc;
      }
    }
  })();
  const invalidShared = await keys.getSharedSymmetricKey(randomBytes(32), notAPoint);
  if (invalidShared !== undefined) throw new Error('expected undefined shared key');

  // Token hashes.
  const tokens = [];
  const pushToken = (tokenData) => {
    const hash = noteUtil.getTokenDataHash(tokenData);
    tokens.push({
      tokenType: tokenData.tokenType,
      tokenAddress: ByteUtils.strip0x(tokenData.tokenAddress),
      tokenSubID: ByteUtils.strip0x(tokenData.tokenSubID),
      tokenHash: hash,
    });
    return { tokenData, hash };
  };
  for (let i = 0; i < 4; i += 1) pushToken(noteUtil.getTokenDataERC20(`0x${hex(randomBytes(20))}`));
  for (let i = 0; i < 4; i += 1) {
    const type = i % 2 ? TokenType.ERC1155 : TokenType.ERC721;
    const subID = i === 0 ? '00' : hex(randomBytes(i === 1 ? 1 : 32));
    pushToken(noteUtil.getTokenDataNFT(`0x${hex(randomBytes(20))}`, type, subID));
  }
  const tokenByHash = new Map(tokens.map((t) => [t.tokenHash, t]));
  const tokenDataGetter = {
    getTokenDataFromHash: async (_v, _c, hash) => {
      const t = tokenByHash.get(ByteUtils.strip0x(hash));
      if (!t) return noteUtil.getTokenDataERC20(hash);
      return noteUtil.serializeTokenData(`0x${t.tokenAddress}`, t.tokenType, `0x${t.tokenSubID}`);
    },
  };

  // Commitments and nullifiers.
  const commitments = [];
  for (let i = 0; i < 8; i += 1) {
    const mpk = randField();
    const random = hex(randomBytes(16));
    const token = tokens[i % tokens.length];
    const value = i === 0 ? 0n : i === 1 ? 2n ** 128n - 1n : BigInt(`0x${hex(randomBytes(12))}`);
    const npk = ShieldNote.getNotePublicKey(mpk, random);
    const hash = TransactNote.getHash(npk, token.tokenHash, value);
    commitments.push({
      masterPublicKey: big(mpk),
      random,
      tokenHash: token.tokenHash,
      value: big(value),
      notePublicKey: big(npk),
      commitment: big(hash),
    });
  }
  const nullifiers = [];
  for (const w of wallets.slice(0, 4)) {
    for (const leafIndex of [0, 1, 65535, 3141]) {
      const nk = BigInt(w.nullifyingKey);
      nullifiers.push({ nullifyingKey: w.nullifyingKey, leafIndex, nullifier: big(TransactNote.getNullifier(nk, leafIndex)) });
    }
  }

  // Wallet sources and annotation data.
  const SOURCES = ['railway', '', 'railgun wallet 1', 'zzzzzzzzzzzzzzzz', 'a', 'Gem Wallet'];
  const walletSources = SOURCES.map((s) => ({ walletSource: s, encoded: WalletInfo.getEncodedWalletSource(s) }));
  const annotations = [];
  for (let i = 0; i < 12; i += 1) {
    const viewingPrivateKey = randomBytes(32);
    const outputType = [OutputType.Transfer, OutputType.BroadcasterFee, OutputType.Change][i % 3];
    const senderRandom = i % 4 === 0 ? MEMO_SENDER_RANDOM_NULL : hex(randomBytes(15));
    const walletSource = SOURCES[i % SOURCES.length];
    const iv = hex(randomBytes(16));
    queue.push(iv);
    const annotationData = Memo.createEncryptedNoteAnnotationDataV2(outputType, senderRandom, walletSource, viewingPrivateKey);
    expectQueueEmpty();
    const decrypted = Memo.decryptNoteAnnotationData(annotationData, viewingPrivateKey);
    annotations.push({
      viewingPrivateKey: hex(viewingPrivateKey),
      outputType,
      senderRandom,
      walletSource,
      iv,
      annotationData,
      decrypted: {
        outputType: decrypted.outputType,
        senderRandom: decrypted.senderRandom,
        walletSource: decrypted.walletSource ?? null,
      },
    });
  }

  // Memo text encoding.
  const MEMOS = [undefined, '', 'hello', '送金テスト 🚀', 'x'.repeat(100)];

  // V2 transact notes, encrypted by the sender and decrypted by both sides.
  const transactNotes = [];
  const chain = { type: 0, id: 11155111 };
  const addressOf = (w) => ({
    masterPublicKey: BigInt(w.masterPublicKey),
    viewingPublicKey: ByteUtils.hexToBytes(w.viewingPublicKey),
  });
  for (let i = 0; i < 12; i += 1) {
    const sender = wallets[(i * 5) % wallets.length];
    const receiver = wallets[(i * 5 + 13) % wallets.length];
    const token = tokens[i % tokens.length];
    let value = BigInt(`0x${hex(randomBytes(i % 2 ? 16 : 8))}`);
    if (token.tokenType === TokenType.ERC721) value = 1n;
    const showSender = i % 3 !== 1;
    const senderRandom = showSender ? MEMO_SENDER_RANDOM_NULL : hex(randomBytes(15));
    const random = hex(randomBytes(16));
    const outputType = [OutputType.Transfer, OutputType.BroadcasterFee, OutputType.Change][i % 3];
    const walletSource = SOURCES[i % SOURCES.length];
    const memoText = MEMOS[i % MEMOS.length];
    const tokenData = await tokenDataGetter.getTokenDataFromHash(null, chain, token.tokenHash);

    const note = new TransactNote(
      addressOf(receiver), addressOf(sender), random, value, tokenData, outputType,
      walletSource, senderRandom, memoText, undefined, undefined,
    );
    const senderViewPriv = ByteUtils.hexToBytes(sender.viewingPrivateKey);
    const receiverViewPriv = ByteUtils.hexToBytes(receiver.viewingPrivateKey);
    const b = keys.getNoteBlindingKeys(
      ByteUtils.hexToBytes(sender.viewingPublicKey), ByteUtils.hexToBytes(receiver.viewingPublicKey),
      random, senderRandom,
    );
    const sharedKey = await keys.getSharedSymmetricKey(senderViewPriv, b.blindedReceiverViewingKey);
    const gcmIv = hex(randomBytes(16));
    const ctrIv = hex(randomBytes(16));
    queue.push(gcmIv, ctrIv);
    const enc = note.encryptV2(TXIDVersion.V2_PoseidonMerkle, sharedKey, BigInt(sender.masterPublicKey), senderRandom, senderViewPriv);
    expectQueueEmpty();
    const ciphertext = [
      `${enc.noteCiphertext.iv}${enc.noteCiphertext.tag}`,
      ...enc.noteCiphertext.data,
    ];

    const asReceiver = await TransactNote.decrypt(
      TXIDVersion.V2_PoseidonMerkle, chain, addressOf(receiver), enc.noteCiphertext,
      await keys.getSharedSymmetricKey(receiverViewPriv, b.blindedSenderViewingKey),
      enc.noteMemo, enc.annotationData, receiverViewPriv,
      b.blindedReceiverViewingKey, b.blindedSenderViewingKey, false, false, tokenDataGetter, undefined, undefined,
    );
    const asSender = await TransactNote.decrypt(
      TXIDVersion.V2_PoseidonMerkle, chain, addressOf(sender), enc.noteCiphertext, sharedKey,
      enc.noteMemo, enc.annotationData, senderViewPriv,
      b.blindedReceiverViewingKey, b.blindedSenderViewingKey, true, false, tokenDataGetter, undefined, undefined,
    );
    const view = (n) => ({
      receiverMasterPublicKey: big(n.receiverAddressData.masterPublicKey),
      receiverViewingPublicKey: hex(n.receiverAddressData.viewingPublicKey),
      senderMasterPublicKey: n.senderAddressData ? big(n.senderAddressData.masterPublicKey) : null,
      senderViewingPublicKey: n.senderAddressData ? hex(n.senderAddressData.viewingPublicKey) : null,
      random: n.random,
      value: big(n.value),
      tokenHash: n.tokenHash,
      memoText: n.memoText ?? null,
      outputType: n.outputType ?? null,
      walletSource: n.walletSource ?? null,
      senderRandom: n.senderRandom ?? null,
      commitment: big(n.hash),
    });
    if (asReceiver.hash !== note.hash || asSender.hash !== note.hash) throw new Error('note hash');

    transactNotes.push({
      senderViewingPrivateKey: sender.viewingPrivateKey,
      senderViewingPublicKey: sender.viewingPublicKey,
      senderMasterPublicKey: sender.masterPublicKey,
      receiverViewingPrivateKey: receiver.viewingPrivateKey,
      receiverViewingPublicKey: receiver.viewingPublicKey,
      receiverMasterPublicKey: receiver.masterPublicKey,
      tokenHash: token.tokenHash,
      value: big(value),
      random,
      senderRandom,
      outputType,
      walletSource,
      memoText: memoText ?? null,
      gcmIv,
      ctrIv,
      notePublicKey: big(note.notePublicKey),
      commitment: big(note.hash),
      blindedSenderViewingKey: hex(b.blindedSenderViewingKey),
      blindedReceiverViewingKey: hex(b.blindedReceiverViewingKey),
      sharedKey: hex(sharedKey),
      ciphertext,
      memo: enc.noteMemo,
      annotationData: enc.annotationData,
      decryptedByReceiver: view(asReceiver),
      decryptedBySender: view(asSender),
    });
  }

  // Shield ciphertexts.
  const shields = [];
  for (let i = 0; i < 8; i += 1) {
    const receiver = wallets[(i * 7 + 3) % wallets.length];
    const shieldPrivateKey = randomBytes(32);
    const random = hex(randomBytes(16));
    const value = BigInt(`0x${hex(randomBytes(12))}`);
    const tokenAddress = `0x${hex(randomBytes(20))}`;
    const gcmIv = hex(randomBytes(16));
    const ctrIv = hex(randomBytes(16));
    queue.push(gcmIv, ctrIv);
    const note = new ShieldNoteERC20(BigInt(receiver.masterPublicKey), random, value, tokenAddress);
    const req = await note.serialize(shieldPrivateKey, ByteUtils.hexToBytes(receiver.viewingPublicKey));
    expectQueueEmpty();
    const shieldKey = ByteUtils.strip0x(req.ciphertext.shieldKey);
    const sharedKey = await keys.getSharedSymmetricKey(
      ByteUtils.hexToBytes(receiver.viewingPrivateKey), ByteUtils.hexToBytes(shieldKey),
    );
    const decryptedRandom = ShieldNote.decryptRandom(req.ciphertext.encryptedBundle, sharedKey);
    if (decryptedRandom !== random) throw new Error('shield random');
    shields.push({
      receiverViewingPrivateKey: receiver.viewingPrivateKey,
      receiverViewingPublicKey: receiver.viewingPublicKey,
      receiverMasterPublicKey: receiver.masterPublicKey,
      shieldPrivateKey: hex(shieldPrivateKey),
      random,
      value: big(value),
      tokenAddress: ByteUtils.strip0x(tokenAddress),
      tokenHash: note.tokenHash,
      gcmIv,
      ctrIv,
      notePublicKey: ByteUtils.strip0x(req.preimage.npk),
      commitment: big(ShieldNote.getShieldNoteHash(note.notePublicKey, note.tokenHash, value)),
      shieldKey,
      encryptedBundle: req.ciphertext.encryptedBundle.map((x) => ByteUtils.strip0x(x)),
      sharedKey: hex(sharedKey),
    });
  }

  return {
    'eddsa.json': eddsa,
    'ed25519.json': { scalars, blinding, invalidPoint: hex(notAPoint) },
    'notes.json': {
      tokens,
      commitments,
      nullifiers,
      walletSources,
      memos: MEMOS.filter((m) => m !== undefined).map((m) => ({ text: m, encoded: Memo.encodeMemoText(m) })),
      annotations,
      transactNotes,
      shields,
    },
  };
};
