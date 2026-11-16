import QtQuick
import Quickshell
import Quickshell.Io

// TEST FIXTURE, never loaded.
Item {
  Process {
    running: true
    command: ["python3", Qt.resolvedUrl("collect.py").toString().replace("file://", "")]
  }
  Process {
    running: true
    command: ["bash", Qt.resolvedUrl("install.sh").toString().replace("file://", "")]
  }
}
