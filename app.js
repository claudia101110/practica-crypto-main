let parellXifrat;
let parellSignatura;

function bufferABase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ABuffer(base64) {
  const binari = atob(base64);
  const bytes = new Uint8Array(binari.length);
  for (let i = 0; i < binari.length; i++) {
    bytes[i] = binari.charCodeAt(i);
  }
  return bytes;
}

const btnGenerar = document.getElementById("btnGenerar");

btnGenerar.addEventListener("click", async () => {
  parellXifrat = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );

  console.log(parellXifrat);
  let pubJWK = await crypto.subtle.exportKey("jwk", parellXifrat.publicKey);
  document.getElementById("miPubCifrado").value = JSON.stringify(pubJWK);

  let privJWK = await crypto.subtle.exportKey("jwk", parellXifrat.privateKey);
  document.getElementById("miPrivCifrado").value = JSON.stringify(privJWK);

  parellSignatura = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );

  let pubSig = await crypto.subtle.exportKey("jwk", parellSignatura.publicKey);
  document.getElementById("miPubFirma").value = JSON.stringify(pubSig);

  let privSig = await crypto.subtle.exportKey(
    "jwk",
    parellSignatura.privateKey,
  );
  document.getElementById("miPrivFirma").value = JSON.stringify(privSig);
});
document.getElementById("btnFirmar").addEventListener("click", async () => {
  const text = document.getElementById("mensaje").value;
  const dades = new TextEncoder().encode(text);
  const signatura = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    parellSignatura.privateKey,
    dades,
  );
  const signaturaB64 = bufferABase64(signatura);
  const objecte = { missatge: text, signatura: signaturaB64 };
  document.getElementById("mensaje").value = JSON.stringify(objecte, null, 2);
});

document.getElementById("btnCifrar").addEventListener("click", async () => {
  const textJSON = document.getElementById("mensaje").value;
  const jwk = JSON.parse(document.getElementById("remotaPubCifrado").value);
  const clauPublica = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"],
  );

  const claveAES = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const dadesXifrades = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    claveAES,
    new TextEncoder().encode(textJSON),
  );
  const aesRaw = await crypto.subtle.exportKey("raw", claveAES);
  const claveAESXifrada = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    clauPublica,
    aesRaw,
  );
  const paquet = {
    clauAES: bufferABase64(claveAESXifrada),
    iv: bufferABase64(iv),
    dades: bufferABase64(dadesXifrades),
  };
  document.getElementById("salidaCifrada").value = JSON.stringify(paquet);
});

document.getElementById("btnDescifrar").addEventListener("click", async () => {
  const paquet = JSON.parse(document.getElementById("entradaCifrada").value);

  const clauAESXifrada = base64ABuffer(paquet.clauAES);
  const iv = base64ABuffer(paquet.iv);
  const dades = base64ABuffer(paquet.dades);

  const aesRaw = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    parellXifrat.privateKey,
    clauAESXifrada,
  );

  const claveAES = await crypto.subtle.importKey(
    "raw",
    aesRaw,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const dadesBytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    claveAES,
    dades,
  );

  const text = new TextDecoder().decode(dadesBytes);
  const contingut = JSON.parse(text);

  const jwkSig = JSON.parse(document.getElementById("remotaPubFirma").value);
  const clauVerificar = await crypto.subtle.importKey(
    "jwk",
    jwkSig,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"],
  );

  const valida = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    clauVerificar,
    base64ABuffer(contingut.signatura),
    new TextEncoder().encode(contingut.missatge),
  );

  document.getElementById("resultadoMensaje").textContent = contingut.missatge;
  document.getElementById("resultadoFirma").textContent = valida
    ? "Signatura vàlida"
    : "Signatura trencada";
});
