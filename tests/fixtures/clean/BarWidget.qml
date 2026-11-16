import QtQuick
import qs.Commons
import qs.Ui
import "Format.js" as Format

// A bar label that shows the current seconds. No processes, no files, no network.
BarWidget {
  id: root
  moduleName: "fixture.clean-clock"
  property date now: new Date()

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  Timer {
    interval: 1000
    running: true
    repeat: true
    onTriggered: root.now = new Date()
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: Format.seconds(root.now)
  }
}
