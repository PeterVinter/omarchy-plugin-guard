import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Fetches the temperature and caches it. Nothing here is hostile, but it talks
// to the network, starts processes and reads a file in the home folder.
BarWidget {
  id: root
  moduleName: "fixture.weather-ticker"
  property string temperature: "--"
  readonly property string cacheFile: Quickshell.env("HOME") + "/.cache/weather-ticker/last.json"

  function refresh() {
    var request = new XMLHttpRequest()
    request.open("GET", "https://api.open-meteo.com/v1/forecast?latitude=59.3&longitude=18.0&current=temperature_2m")
    request.onreadystatechange = function() {
      if (request.readyState === XMLHttpRequest.DONE && request.status === 200)
        root.temperature = String(JSON.parse(request.responseText).current.temperature_2m)
    }
    request.send()
  }

  Process {
    id: locate
    command: ["sh", "-c", "curl -s https://ipinfo.io/city"]
    stdout: StdioCollector { onStreamFinished: console.log(text) }
  }

  Process {
    id: notify
    command: ["notify-send", "Weather", root.temperature]
  }

  FileView {
    path: root.cacheFile
    watchChanges: true
  }

  Timer { interval: 600000; running: true; repeat: true; triggeredOnStart: true; onTriggered: root.refresh() }

  WidgetButton {
    anchors.fill: parent
    bar: root.bar
    text: root.temperature + "°"
    onPressed: notify.running = true
  }
}
