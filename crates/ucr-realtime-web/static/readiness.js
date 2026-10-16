// Independent from the E2EE media module: show an actionable status even if
// start.js cannot be evaluated because its media dependency is unavailable.
(async () => {
  const output = document.getElementById("video-readiness");
  try {
    const response = await fetch("/readyz", {cache:"no-store", credentials:"same-origin"});
    output.textContent = response.ok
      ? "Медиашлюз готов. Для звонка нужны два доверенных устройства и принятый вызов."
      : "Медиа пока недоступно (HTTP " + response.status + "). Проверьте BFF авторизации и сборку браузерных E2EE-модулей.";
  } catch {
    output.textContent = "Проверка медиашлюза не удалась. Убедитесь, что сервер запущен.";
  }
})();
