// Outlook .msg files: pull out the internet (transport) headers.
const MsgReader = require('@kenjiuno/msgreader').default;

const OLE_MAGIC = Buffer.from('d0cf11e0a1b11ae1', 'hex');

const isMsg = buf => buf.length >= 8 && buf.subarray(0, 8).equals(OLE_MAGIC);

function msgHeaders(buf) {
  let data;
  try {
    data = new MsgReader(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)).getFileData();
  } catch (err) {
    throw new Error(`Could not read the .msg file (${err.message}).`);
  }
  if (data.error) throw new Error(`Could not read the .msg file (${data.error}).`);
  if (!data.headers || !data.headers.trim()) {
    throw new Error('This .msg file has no internet headers. Drafts and messages you sent yourself don\'t carry them - open a message you received, or paste the headers instead.');
  }
  // Header text is Unicode; convert to UTF-8 bytes like pasted text.
  return Buffer.from(data.headers, 'utf8').toString('latin1');
}

module.exports = { isMsg, msgHeaders };
