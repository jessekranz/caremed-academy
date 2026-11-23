/* Slow the short caption briefings so each caption can be read (secure portal media page). */
document.querySelectorAll('video').forEach(function (v) {
  var rate = 0.4;
  v.defaultPlaybackRate = rate;
  v.playbackRate = rate;
  v.addEventListener('loadedmetadata', function () { v.playbackRate = rate; });
});
