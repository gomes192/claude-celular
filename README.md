# claude-celular

Página estática para responder, pelo celular, perguntas enviadas por um mod do Claude Code via [ntfy](https://ntfy.sh).

- Não guarda nem contém segredos: a chave nasce de um código de pareamento digitado no celular e fica só no navegador (localStorage).
- Perguntas e respostas viajam cifradas e assinadas (`cifra.js`: SHA-256 em modo contador + HMAC-SHA256, chave derivada com PBKDF2).
- Sem scripts externos, sem analytics, sem referrer.
