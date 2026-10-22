// Independent from the E2EE media module: show an actionable status even if
// start.js cannot be evaluated because its media dependency is unavailable.
(async () => {
  const output = document.getElementById("video-readiness");
  try {
    const response = await fetch("/readyz", {cache:"no-store", credentials:"same-origin"});
    output.textContent = response.ok
      // /readyz checks only the sign-in BFF and the browser E2EE assets; the
      // media path (realtime, SFU, TURN) is verified when a call connects.
      ? "Сервер входа и браузерные E2EE-модули доступны. Медиасоединение проверяется при подключении к звонку: нужны два доверенных устройства и принятый вызов."
      : "Медиа пока недоступно (HTTP " + response.status + "). Проверьте BFF авторизации и сборку браузерных E2EE-модулей.";
  } catch {
    output.textContent = "Проверка готовности сервера не удалась. Убедитесь, что сервер запущен.";
  }
})();
