import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Risk.js" as Risk

// Plugin Guard: a shield in the bar and a panel that scans a third-party
// plugin's git repository before it is installed.
//
// All scanning lives in scanner.py; this file only starts it and draws the
// result it writes to ~/.local/state/plugin-guard/last.json. Everything shown
// from a scan (file names, code snippets, diff lines, manifest fields) is
// untrusted text, so every Text here is Text.PlainText.
//
// Colours, fonts, radius and spacing come from qs.Commons (Color, Style),
// which the shell updates in place on a theme switch. The three risk colours
// are the theme's own green, yellow and red from colors.toml, re-read on every
// switch and checked for hue and contrast in Risk.js.
Panel {
  id: root
  moduleName: "peter.plugin-guard"
  ipcTarget: "peter.plugin-guard"
  manageIpc: false

  // ------------------------------------------------------------------ state

  property var result: null            // parsed last.json, or null
  property string phase: "idle"        // idle | scanning | installing
  property string stage: ""
  property string urlText: ""
  property string shaText: ""
  property string confirming: ""       // "" | "head" | "verified"
  property string installError: ""
  property real resultStamp: 0
  property bool openHigh: true
  property bool openMedium: false
  property bool openInfo: false
  property bool openDiff: false

  readonly property string view: phase === "scanning" ? "scanning"
    : (!result ? "empty" : (result.ok ? "result" : "error"))
  readonly property string verdict: view === "result" ? String(result.verdict || "") : ""
  readonly property var counts: view === "result" && result.counts ? result.counts : ({ high: 0, medium: 0, info: 0 })
  readonly property var diff: view === "result" && result.diff ? result.diff : null
  readonly property bool movedPastVerified: !!diff && diff.ok === true && diff.identical === false
  readonly property bool installable: view === "result" && !!result.id && !!result.pluginId && !result.installed
  readonly property bool busy: phase !== "idle"

  readonly property string scannerPath: Qt.resolvedUrl("scanner.py").toString().replace(/^file:\/\//, "")
  readonly property string stateHome: Quickshell.env("XDG_STATE_HOME") || (Quickshell.env("HOME") + "/.local/state")

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  // ------------------------------------------------------------------ theme

  readonly property color fg: Commons.Color.popups.text
  readonly property color dim: Qt.rgba(fg.r, fg.g, fg.b, 0.62)
  readonly property color faint: Qt.rgba(fg.r, fg.g, fg.b, 0.4)
  readonly property color accent: Commons.Color.accent
  readonly property string fontFamily: Style.font.family
  readonly property color barFg: bar ? bar.barForeground : Commons.Color.bar.text

  // Named colours of the active theme (green, yellow, red, ...).
  property var themeColors: ({})

  function hex(c) {
    function part(v) {
      var s = Math.max(0, Math.min(255, Math.round(v * 255))).toString(16)
      return s.length < 2 ? "0" + s : s
    }
    return "#" + part(c.r) + part(c.g) + part(c.b)
  }

  readonly property string panelBgHex: hex(Commons.Color.popups.background)
  readonly property string barBgHex: hex(Commons.Color.bar.background)
  readonly property string urgentHex: hex(Commons.Color.urgent)

  readonly property color safeColor: Risk.levelColor(themeColors, "safe", urgentHex, panelBgHex, hex(fg), 3)
  readonly property color cautionColor: Risk.levelColor(themeColors, "caution", urgentHex, panelBgHex, hex(fg), 3)
  readonly property color dangerColor: Risk.levelColor(themeColors, "danger", urgentHex, panelBgHex, hex(fg), 3)
  readonly property color infoColor: Risk.readable(hex(accent), panelBgHex, hex(fg), 3)

  function tone(level) {
    if (level === "danger" || level === "high") return dangerColor
    if (level === "caution" || level === "medium") return cautionColor
    if (level === "safe") return safeColor
    if (level === "info") return infoColor
    return dim
  }

  // The same levels against the bar's own background, which can differ.
  readonly property color barTone: {
    if (view !== "result") return view === "error" ? Risk.levelColor(themeColors, "danger", urgentHex, barBgHex, hex(barFg), 3) : barFg
    return Risk.levelColor(themeColors, verdict, urgentHex, barBgHex, hex(barFg), 3)
  }

  // The shell pushes a new palette into Commons.Color over IPC; the theme's
  // colors.toml is already in place by then, so read it again.
  FileView {
    id: paletteFile
    path: Quickshell.env("HOME") + "/.local/state/omarchy/current/theme/colors.toml"
    watchChanges: true
    printErrors: false
    onLoaded: root.themeColors = Risk.parseColors(text())
    onLoadFailed: root.themeColors = ({})
    onFileChanged: paletteReload.restart()
  }
  FileView {
    path: Quickshell.env("HOME") + "/.local/state/omarchy/current/theme.name"
    watchChanges: true
    printErrors: false
    onFileChanged: paletteReload.restart()
  }
  Connections {
    target: Commons.Color
    function onBackgroundChanged() { paletteReload.restart() }
    function onForegroundChanged() { paletteReload.restart() }
    function onAccentChanged() { paletteReload.restart() }
    function onUrgentChanged() { paletteReload.restart() }
  }
  Timer { id: paletteReload; interval: 60; onTriggered: paletteFile.reload() }

  // ---------------------------------------------------------------- glyphs

  readonly property string glyphIdle: String.fromCodePoint(0xF0499)     // shield outline
  readonly property string glyphSafe: String.fromCodePoint(0xF0565)     // shield check
  readonly property string glyphCaution: String.fromCodePoint(0xF0ECD)  // shield alert outline
  readonly property string glyphDanger: String.fromCodePoint(0xF0ECC)   // shield alert
  readonly property string glyphError: String.fromCodePoint(0xF099E)    // shield off
  readonly property string glyphScan: String.fromCodePoint(0xF0D9A)     // shield search
  readonly property string glyphChevron: String.fromCodePoint(0xF0142)

  readonly property string stateGlyph: view === "scanning" ? glyphScan
    : view === "error" ? glyphError
    : verdict === "safe" ? glyphSafe
    : verdict === "caution" ? glyphCaution
    : verdict === "danger" ? glyphDanger
    : glyphIdle

  readonly property string heroTitle: view === "scanning" ? strings.t("scanning.title")
    : view === "error" ? strings.t("verdict.error")
    : view === "result" ? strings.t("verdict." + verdict, verdict)
    : strings.t("title")

  readonly property string heroMeta: {
    if (view === "scanning") return strings.t("stage." + stage, stage)
    if (view === "error") return String(result.url || "")
    if (view !== "result") return strings.t("idle.meta")
    var m = result.manifest || {}
    if (!m.id) return strings.t("meta.unknownPlugin")
    return (m.name || m.id) + (m.version ? " " + m.version : "") + "  ·  " + m.id
  }

  readonly property color heroColor: view === "result" ? tone(verdict) : (view === "error" ? dangerColor : fg)

  // ---------------------------------------------------------------- result

  FileView {
    id: lastFile
    path: root.stateHome + "/plugin-guard/last.json"
    watchChanges: true
    printErrors: false
    onLoaded: root.applyResult(text())
    onLoadFailed: root.applyResult("")
    onFileChanged: reload()
  }

  function applyResult(raw) {
    var parsed = null
    try {
      parsed = raw ? JSON.parse(raw) : null
    } catch (e) {
      parsed = null
    }
    if (parsed && typeof parsed !== "object") parsed = null
    result = parsed
    var stamp = parsed ? Number(parsed.scannedAt) || 0 : 0
    if (stamp !== resultStamp) {
      resultStamp = stamp
      confirming = ""
      installError = ""
      var c = parsed && parsed.ok && parsed.counts ? parsed.counts : { high: 0, medium: 0 }
      openHigh = c.high > 0
      openMedium = c.high === 0 && c.medium > 0
      openInfo = false
      openDiff = !!(parsed && parsed.ok && parsed.diff && parsed.diff.ok && !parsed.diff.identical)
      if (parsed && parsed.url && urlText === "") urlText = String(parsed.url)
      if (parsed && parsed.ok && parsed.verified && shaText === "") shaText = String(parsed.verified)
    }
  }

  function startScan() {
    if (busy) return
    var url = urlText.trim()
    var sha = shaText.trim()
    confirming = ""
    installError = ""
    if (url === "") {
      result = { ok: false, url: "", scannedAt: 0, error: { code: "invalid-url", message: strings.t("error.emptyUrl") } }
      return
    }
    var command = ["python3", "-I", scannerPath, "scan", "--json"]
    if (sha !== "") command.push("--verified", sha)
    command.push("--", url)
    stage = "cloning"
    phase = "scanning"
    worker.command = command
    worker.running = true
  }

  function requestInstall(which) {
    if (!installable || busy) return
    installError = ""
    confirming = which
  }

  // Only reached from the Confirm button, after the question naming the
  // plugin and the commit has been on screen.
  function confirmInstall() {
    if (!installable || busy || confirming === "") return
    var command = ["python3", "-I", scannerPath, "install", "--json", "--yes"]
    if (confirming === "verified") command.push("--commit", String(result.verified))
    command.push("--", String(result.id))
    stage = "installing"
    phase = "installing"
    worker.command = command
    worker.running = true
  }

  function clearLast() {
    if (busy) return
    worker.command = ["python3", "-I", scannerPath, "clean"]
    worker.running = true
  }

  Process {
    id: worker
    stdout: StdioCollector { id: workerOut }
    stderr: SplitParser {
      onRead: function(line) {
        if (String(line).indexOf("stage:") === 0) root.stage = String(line).substring(6)
      }
    }
    onExited: function(code) {
      var wasInstall = root.phase === "installing"
      root.phase = "idle"
      root.stage = ""
      if (wasInstall) {
        root.confirming = ""
        try {
          var reply = JSON.parse(workerOut.text)
          root.installError = reply && reply.ok ? "" : String(reply && reply.error ? reply.error.message : strings.t("install.failed"))
        } catch (e) {
          root.installError = strings.t("install.failed")
        }
      }
      lastFile.reload()
    }
  }

  // --------------------------------------------------------------- shell IPC

  ShellIpc {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function scan(url: string): string {
      root.urlText = String(url || "").slice(0, 2000)
      root.shaText = ""
      root.open()
      root.startScan()
      return "ok"
    }
    function scanVerified(url: string, sha: string): string {
      root.urlText = String(url || "").slice(0, 2000)
      root.shaText = String(sha || "").slice(0, 64)
      root.open()
      root.startScan()
      return "ok"
    }
    // high | medium | info | diff | all | none
    function expand(section: string): string {
      root.openHigh = section === "high" || section === "all"
      root.openMedium = section === "medium" || section === "all"
      root.openInfo = section === "info" || section === "all"
      root.openDiff = section === "diff" || section === "all"
      return "ok"
    }
    function state(): string {
      return JSON.stringify({ view: root.view, verdict: root.verdict, phase: root.phase, opened: root.opened,
        safe: String(root.safeColor), caution: String(root.cautionColor), danger: String(root.dangerColor) })
    }
  }

  onOpenedChanged: {
    if (!opened) {
      confirming = ""
      return
    }
    Qt.callLater(function() {
      if (panel.loadedContent) panel.loadedContent.forceActiveFocus()
    })
  }

  // -------------------------------------------------------------- bar icon

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.stateGlyph
    foreground: root.barTone
    dimmed: root.phase === "scanning" && pulse.dimPhase
    tooltipText: root.view === "scanning" ? strings.t("tooltip.scanning")
      : root.view === "result" ? strings.t("tooltip.result").arg(root.heroTitle).arg(String((root.result.manifest || {}).name || root.result.url || ""))
      : strings.t("tooltip.idle")
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.MiddleButton) root.clearLast()
      else root.toggle()
    }
  }

  // The bar icon breathes while a scan runs.
  Timer {
    id: pulse
    property bool dimPhase: false
    interval: 520
    repeat: true
    running: root.phase === "scanning" && !Style.reduceMotion
    onTriggered: dimPhase = !dimPhase
    onRunningChanged: if (!running) dimPhase = false
  }

  // ----------------------------------------------------------------- panel

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(580))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(800))

    content: FocusScope {
      id: body
      anchors.fill: parent
      readonly property int gap: Style.space(12)
      implicitHeight: header.implicitHeight + gap + details.implicitHeight
        + (footer.visible ? gap + footer.implicitHeight : 0)

      Keys.onEscapePressed: root.close()

      // The question appears with focus on Back, so a stray Enter cannot install.
      Connections {
        target: root
        function onConfirmingChanged() {
          if (root.confirming !== "") Qt.callLater(function() { backButton.forceActiveFocus() })
        }
      }

      Column {
        id: header
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: body.gap

        // Verdict
        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.height, heroLabels.implicitHeight)

          Item {
            id: heroIcon
            width: Style.space(52)
            height: Style.space(52)
            anchors.verticalCenter: parent.verticalCenter

            Text {
              textFormat: Text.PlainText
              anchors.centerIn: parent
              visible: !root.busy
              text: root.stateGlyph
              color: root.heroColor
              opacity: root.view === "empty" ? 0.55 : 1
              font.family: root.fontFamily
              font.pixelSize: Style.fontPx(3.6)
              Behavior on color { ColorAnimation { duration: Style.duration(160) } }
            }

            Spinner {
              anchors.centerIn: parent
              visible: root.busy
              size: Style.space(34)
            }
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(14)
            anchors.right: scorePill.visible ? scorePill.left : parent.right
            anchors.rightMargin: scorePill.visible ? Style.space(12) : 0
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.heroTitle
              color: root.heroColor
              font.family: root.fontFamily
              font.pixelSize: Style.font.display
              font.bold: true
              elide: Text.ElideRight
              Behavior on color { ColorAnimation { duration: Style.duration(160) } }
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.heroMeta
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideMiddle
            }
          }

          BorderSurface {
            id: scorePill
            visible: root.view === "result"
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            implicitWidth: scoreColumn.implicitWidth + Style.space(20)
            implicitHeight: scoreColumn.implicitHeight + Style.space(10)
            width: implicitWidth
            height: implicitHeight
            radius: Style.cornerRadius
            color: Qt.rgba(root.heroColor.r, root.heroColor.g, root.heroColor.b, 0.12)
            borderSpec: Border.flat(Qt.rgba(root.heroColor.r, root.heroColor.g, root.heroColor.b, 0.45), Math.max(1, Style.normalBorderWidth))

            Column {
              id: scoreColumn
              anchors.centerIn: parent
              spacing: 0

              Text {
                textFormat: Text.PlainText
                anchors.horizontalCenter: parent.horizontalCenter
                text: root.view === "result" ? String(Number(root.result.score) || 0) : ""
                color: root.heroColor
                font.family: root.fontFamily
                font.pixelSize: Style.font.heading
                font.bold: true
              }
              Text {
                textFormat: Text.PlainText
                anchors.horizontalCenter: parent.horizontalCenter
                text: "RISK / 100"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.letterSpacing: 1
              }
            }
          }
        }

        // Input
        RowLayout {
          width: parent.width
          spacing: Style.spacing.controlGap

          TextField {
            id: urlField
            Layout.fillWidth: true
            focus: true
            enabled: !root.busy
            foreground: root.fg
            placeholderText: strings.t("url.placeholder")
            inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoPredictiveText
            maximumLength: 2000
            selectByMouse: true
            Component.onCompleted: text = root.urlText
            onTextChanged: if (root.urlText !== text) root.urlText = text
            onAccepted: root.startScan()
            Keys.onEscapePressed: root.close()

            Connections {
              target: root
              function onUrlTextChanged() { if (urlField.text !== root.urlText) urlField.text = root.urlText }
            }
          }

          Button {
            Layout.preferredHeight: urlField.implicitHeight
            text: root.view === "result" || root.view === "error" ? strings.t("rescan") : strings.t("scan")
            iconText: root.glyphScan
            bordered: true
            focusable: true
            selected: root.view === "empty"
            enabled: !root.busy
            opacity: enabled ? 1 : 0.45
            foreground: root.fg
            onClicked: root.startScan()
            Keys.onEscapePressed: root.close()
          }
        }

        TextField {
          id: shaField
          width: parent.width
          enabled: !root.busy
          foreground: root.fg
          placeholderText: strings.t("sha.placeholder")
          inputMethodHints: Qt.ImhNoPredictiveText
          maximumLength: 64
          selectByMouse: true
          Component.onCompleted: text = root.shaText
          onTextChanged: if (root.shaText !== text) root.shaText = text
          onAccepted: root.startScan()
          Keys.onEscapePressed: root.close()

          Connections {
            target: root
            function onShaTextChanged() { if (shaField.text !== root.shaText) shaField.text = root.shaText }
          }
        }

        PanelSeparator { foreground: root.fg }
      }

      Flickable {
        id: flick
        anchors.top: header.bottom
        anchors.topMargin: body.gap
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: footer.visible ? footer.top : parent.bottom
        anchors.bottomMargin: footer.visible ? body.gap : 0
        contentWidth: width
        contentHeight: details.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: details
          width: flick.width - (flick.interactive ? Style.space(10) : 0)
          spacing: Style.space(10)

          // Empty, scanning and error states
          StateNote {
            visible: root.view === "empty"
            glyph: root.glyphIdle
            glyphColor: root.faint
            title: strings.t("empty.title")
            text: strings.t("empty.body")
          }

          StateNote {
            visible: root.view === "scanning"
            glyph: ""
            title: strings.t("scanning.note")
            text: root.urlText
            mono: true
          }

          StateNote {
            visible: root.view === "error"
            glyph: root.glyphError
            glyphColor: root.dangerColor
            title: root.view === "error"
              ? strings.t("error." + String(root.result.error ? root.result.error.code : ""), strings.t("error.generic"))
              : ""
            text: root.view === "error" && root.result.error ? String(root.result.error.message || "") : ""
            hint: strings.t("error.hint")
            mono: true
          }

          // Result: summary, counts, then the details
          Text {
            visible: root.view === "result"
            textFormat: Text.PlainText
            width: parent.width
            text: root.view === "result" ? String(root.result.summary || "") : ""
            color: root.fg
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            wrapMode: Text.WordWrap
            lineHeight: 1.25
          }

          Text {
            visible: root.movedPastVerified || (!!root.diff && root.diff.ok === false)
            textFormat: Text.PlainText
            width: parent.width
            text: !root.diff ? "" : (root.diff.ok ? String(root.diff.summary || "") : strings.t("diff.failed") + ": " + String(root.diff.error || ""))
            color: root.cautionColor
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            wrapMode: Text.WordWrap
            lineHeight: 1.25
          }

          RowLayout {
            visible: root.view === "result"
            width: parent.width
            spacing: Style.space(6)

            Chip { label: strings.t("counts.high"); value: root.counts.high; tint: root.dangerColor }
            Chip { label: strings.t("counts.medium"); value: root.counts.medium; tint: root.cautionColor }
            Chip { label: strings.t("counts.info"); value: root.counts.info; tint: root.infoColor }

            Text {
              textFormat: Text.PlainText
              Layout.fillWidth: true
              horizontalAlignment: Text.AlignRight
              text: root.view !== "result" ? ""
                : strings.tn("meta.files", Number(root.result.files) || 0).arg(Number(root.result.files) || 0)
                  + (root.result.head ? "  ·  " + strings.t("meta.head").arg(Risk.shortSha(root.result.head)) : "")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideLeft
            }
          }

          Group {
            visible: root.view === "result"
            title: root.counts.high > 0 ? strings.t("group.high") : strings.t("group.none.high")
            count: root.counts.high
            tint: root.counts.high > 0 ? root.dangerColor : root.safeColor
            expanded: root.openHigh && root.counts.high > 0
            onToggled: root.openHigh = !root.openHigh
            body: Component { FindingList { severity: "high"; tint: root.dangerColor } }
          }

          Group {
            visible: root.view === "result"
            title: root.counts.medium > 0 ? strings.t("group.medium") : strings.t("group.none.medium")
            count: root.counts.medium
            tint: root.counts.medium > 0 ? root.cautionColor : root.safeColor
            expanded: root.openMedium && root.counts.medium > 0
            onToggled: root.openMedium = !root.openMedium
            body: Component { FindingList { severity: "medium"; tint: root.cautionColor } }
          }

          Group {
            visible: root.view === "result"
            title: strings.t("group.info")
            count: root.counts.info
            tint: root.infoColor
            expanded: root.openInfo && root.counts.info > 0
            onToggled: root.openInfo = !root.openInfo
            body: Component { FindingList { severity: "info"; tint: root.infoColor } }
          }

          Group {
            visible: !!root.diff && root.diff.ok === true
            title: strings.t("group.diff")
            count: root.diff && root.diff.ok ? Number(root.diff.filesChanged) || 0 : 0
            tint: root.movedPastVerified ? root.cautionColor : root.safeColor
            expanded: root.openDiff
            onToggled: root.openDiff = !root.openDiff
            body: Component { DiffView {} }
          }
        }
      }

      // Install / Cancel
      Column {
        id: footer
        visible: root.view === "result"
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        spacing: Style.space(10)

        PanelSeparator { foreground: root.fg }

        Text {
          id: footNote
          textFormat: Text.PlainText
          width: parent.width
          visible: text !== ""
          wrapMode: Text.WordWrap
          lineHeight: 1.25
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          color: root.installError !== "" ? root.dangerColor
            : root.confirming !== "" ? (root.verdict === "danger" && root.confirming === "head" ? root.dangerColor : root.fg)
            : root.safeColor
          text: {
            if (root.view !== "result") return ""
            if (root.phase === "installing") return strings.t("stage.installing")
            if (root.installError !== "") return strings.t("install.failed") + ": " + root.installError
            if (root.confirming !== "") {
              var sha = root.confirming === "verified" ? root.result.verified : root.result.head
              return strings.t("install.question").arg(String(root.result.pluginId)).arg(Risk.shortSha(sha)) + " "
                + (root.verdict === "danger" && root.confirming === "head" ? strings.t("install.warningDanger") : strings.t("install.warning"))
            }
            if (root.result.installed)
              return strings.t("install.done").arg(String(root.result.installed.pluginId)).arg(Risk.shortSha(root.result.installed.commit))
                + "\n" + strings.t("install.next").arg(String(root.result.installed.pluginId))
            return ""
          }
        }

        RowLayout {
          width: parent.width
          spacing: Style.spacing.controlGap

          Item { Layout.fillWidth: true }

          Button {
            visible: root.confirming === ""
            text: strings.t("install.cancel")
            bordered: true
            focusable: true
            foreground: root.fg
            onClicked: root.close()
            Keys.onEscapePressed: root.close()
          }

          Button {
            visible: root.confirming === "" && root.installable && !!root.result.verified && root.result.verified !== root.result.head
            text: root.view === "result" ? strings.t("install.verified").arg(Risk.shortSha(root.result.verified)) : ""
            bordered: true
            focusable: true
            selected: true
            enabled: !root.busy
            foreground: root.fg
            onClicked: root.requestInstall("verified")
            Keys.onEscapePressed: root.close()
          }

          Button {
            visible: root.confirming === "" && root.installable
            text: root.view === "result" ? strings.t("install.head").arg(Risk.shortSha(root.result.head)) : ""
            bordered: true
            focusable: true
            selected: !(root.result && root.result.verified && root.result.verified !== root.result.head) && root.verdict !== "danger"
            enabled: !root.busy
            foreground: root.verdict === "danger" ? root.dangerColor : root.fg
            onClicked: root.requestInstall("head")
            Keys.onEscapePressed: root.close()
          }

          Button {
            id: backButton
            visible: root.confirming !== ""
            text: strings.t("install.back")
            bordered: true
            focusable: true
            enabled: !root.busy
            foreground: root.fg
            onClicked: root.confirming = ""
            Keys.onEscapePressed: root.confirming = ""
          }

          Button {
            visible: root.confirming !== ""
            text: strings.t("install.confirm")
            bordered: true
            focusable: true
            selected: true
            enabled: !root.busy
            opacity: enabled ? 1 : 0.45
            foreground: root.verdict === "danger" && root.confirming === "head" ? root.dangerColor : root.fg
            onClicked: root.confirmInstall()
            Keys.onEscapePressed: root.confirming = ""
          }
        }
      }
    }
  }

  // ------------------------------------------------------------ components

  // A ring with a dot running round it. Constant motion, so linear.
  component Spinner: Item {
    id: spinner
    property real size: Style.space(28)
    width: size
    height: size

    Rectangle {
      anchors.fill: parent
      radius: width / 2
      color: "transparent"
      border.width: Math.max(2, Style.space(3))
      border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.16)
    }

    Item {
      anchors.fill: parent
      RotationAnimation on rotation {
        from: 0
        to: 360
        duration: 900
        loops: Animation.Infinite
        running: spinner.visible && !Style.reduceMotion
      }

      Rectangle {
        width: Math.max(4, Style.space(7))
        height: width
        radius: width / 2
        color: root.accent
        anchors.horizontalCenter: parent.horizontalCenter
        y: -Math.round(width / 4)
      }
    }
  }

  // Centered message for the empty, scanning and error states.
  component StateNote: Column {
    id: note
    property string glyph: ""
    property color glyphColor: root.dim
    property string title: ""
    property string text: ""
    property string hint: ""
    property bool mono: false

    width: parent ? parent.width : implicitWidth
    topPadding: Style.space(18)
    bottomPadding: Style.space(22)
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      visible: note.glyph !== ""
      anchors.horizontalCenter: parent.horizontalCenter
      text: note.glyph
      color: note.glyphColor
      font.family: root.fontFamily
      font.pixelSize: Style.fontPx(3.2)
    }

    Text {
      textFormat: Text.PlainText
      width: parent.width
      horizontalAlignment: Text.AlignHCenter
      text: note.title
      color: root.fg
      font.family: root.fontFamily
      font.pixelSize: Style.font.title
      font.bold: true
      wrapMode: Text.WordWrap
    }

    Text {
      textFormat: Text.PlainText
      visible: note.text !== ""
      width: Math.min(parent.width, Style.space(460))
      anchors.horizontalCenter: parent.horizontalCenter
      horizontalAlignment: Text.AlignHCenter
      text: note.text
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: note.mono ? Style.font.bodySmall : Style.font.body
      wrapMode: Text.Wrap
      lineHeight: 1.3
      maximumLineCount: 6
      elide: Text.ElideRight
    }

    Text {
      textFormat: Text.PlainText
      visible: note.hint !== ""
      width: parent.width
      horizontalAlignment: Text.AlignHCenter
      text: note.hint
      color: root.faint
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }
  }

  // "HIGH 3"
  component Chip: BorderSurface {
    id: chip
    property string label: ""
    property int value: 0
    property color tint: root.fg
    readonly property color shown: value > 0 ? tint : root.faint

    implicitWidth: chipRow.implicitWidth + Style.space(16)
    implicitHeight: chipRow.implicitHeight + Style.space(8)
    radius: Style.cornerRadius
    color: value > 0 ? Qt.rgba(tint.r, tint.g, tint.b, 0.13) : "transparent"
    borderSpec: Border.flat(Qt.rgba(shown.r, shown.g, shown.b, value > 0 ? 0.5 : 0.6), Math.max(1, Style.normalBorderWidth))

    Row {
      id: chipRow
      anchors.centerIn: parent
      spacing: Style.space(6)

      Text {
        textFormat: Text.PlainText
        text: chip.label.toUpperCase()
        color: chip.shown
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 1
        anchors.verticalCenter: parent.verticalCenter
      }
      Text {
        textFormat: Text.PlainText
        text: String(chip.value)
        color: chip.value > 0 ? root.fg : root.faint
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        font.bold: true
        anchors.verticalCenter: parent.verticalCenter
      }
    }
  }

  // Collapsible section: a header row that takes hover, Tab focus and
  // Enter/Space, and a body that opens under it.
  component Group: Column {
    id: group
    property string title: ""
    property int count: 0
    property color tint: root.fg
    property bool expanded: false
    property Component body: null
    readonly property bool canOpen: count > 0
    signal toggled()

    width: parent ? parent.width : implicitWidth
    spacing: 0

    CursorSurface {
      id: head
      width: parent.width
      height: implicitHeight
      implicitHeight: headRow.implicitHeight + Style.space(14)
      foreground: root.fg
      accent: root.accent
      bordered: true
      hasCursor: group.canOpen && (headMouse.containsMouse || head.activeFocus)
      activeFocusOnTab: group.canOpen

      Keys.onReturnPressed: group.toggled()
      Keys.onEnterPressed: group.toggled()
      Keys.onSpacePressed: group.toggled()
      Keys.onEscapePressed: root.close()

      MouseArea {
        id: headMouse
        anchors.fill: parent
        hoverEnabled: true
        enabled: group.canOpen
        cursorShape: group.canOpen ? Qt.PointingHandCursor : Qt.ArrowCursor
        onClicked: group.toggled()
      }

      RowLayout {
        id: headRow
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: Style.space(10)
        anchors.rightMargin: Style.space(10)
        spacing: Style.space(8)

        Text {
          textFormat: Text.PlainText
          text: root.glyphChevron
          color: group.canOpen ? root.dim : "transparent"
          font.family: root.fontFamily
          font.pixelSize: Style.font.icon
          rotation: group.expanded ? 90 : 0
          Behavior on rotation {
            NumberAnimation { duration: Style.duration(160); easing.type: Easing.Bezier; easing.bezierCurve: Style.easeOut }
          }
        }

        Rectangle {
          implicitWidth: Style.space(8)
          implicitHeight: Style.space(8)
          radius: width / 2
          color: group.tint
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: group.title
          color: root.fg
          font.family: root.fontFamily
          font.pixelSize: Style.font.subtitle
          font.bold: true
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          visible: group.count > 0
          text: String(group.count)
          color: group.tint
          font.family: root.fontFamily
          font.pixelSize: Style.font.subtitle
          font.bold: true
        }
      }
    }

    Item {
      id: drawer
      width: parent.width
      clip: true
      height: group.expanded ? bodyLoader.implicitHeight + Style.space(10) : 0
      opacity: group.expanded ? 1 : 0

      Behavior on height {
        NumberAnimation { duration: Style.duration(180); easing.type: Easing.Bezier; easing.bezierCurve: Style.easeOut }
      }
      Behavior on opacity {
        NumberAnimation { duration: Style.duration(group.expanded ? 180 : 120); easing.type: Easing.OutCubic }
      }

      Loader {
        id: bodyLoader
        y: Style.space(10)
        width: parent.width
        active: group.expanded || drawer.height > 0
        sourceComponent: group.body
      }
    }
  }

  component FindingList: Column {
    id: list
    property string severity: "high"
    property color tint: root.fg
    readonly property var all: root.view === "result" ? Risk.bySeverity(root.result.findings, severity) : []
    readonly property int limit: 60
    readonly property int hidden: Math.max(0, (root.view === "result" ? Number(root.counts[severity]) || 0 : 0) - Math.min(all.length, limit))

    width: parent ? parent.width : implicitWidth
    spacing: Style.space(10)

    Repeater {
      model: list.all.slice(0, list.limit)
      FindingRow {
        required property var modelData
        width: list.width
        finding: modelData
        tint: list.tint
      }
    }

    Text {
      textFormat: Text.PlainText
      visible: list.hidden > 0
      width: parent.width
      text: strings.tn("more", list.hidden).arg(list.hidden)
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }

  // One finding: what and where, then the offending line with the match
  // picked out in the level's colour.
  component FindingRow: Column {
    id: row
    property var finding: ({})
    property color tint: root.fg
    readonly property var parts: Risk.snippetParts(finding.snippet, finding.matchStart, finding.matchEnd)
    readonly property string where: String(finding.file || "") + (finding.line ? ":" + finding.line : "")

    spacing: Style.space(4)
    leftPadding: Style.space(10)
    rightPadding: Style.space(2)

    RowLayout {
      width: row.width - row.leftPadding - row.rightPadding
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        Layout.fillWidth: true
        text: String(row.finding.title || row.finding.rule || "")
        color: root.fg
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        elide: Text.ElideRight
      }

      BorderSurface {
        visible: row.finding.new === true
        implicitWidth: newLabel.implicitWidth + Style.space(10)
        implicitHeight: newLabel.implicitHeight + Style.space(2)
        radius: Style.cornerRadius
        color: Qt.rgba(root.cautionColor.r, root.cautionColor.g, root.cautionColor.b, 0.16)

        Text {
          id: newLabel
          textFormat: Text.PlainText
          anchors.centerIn: parent
          text: strings.t("new").toUpperCase()
          color: root.cautionColor
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
          font.letterSpacing: 1
        }
      }

      Text {
        textFormat: Text.PlainText
        visible: row.where !== ""
        Layout.maximumWidth: row.width * 0.45
        text: row.where
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        elide: Text.ElideLeft
      }
    }

    Rectangle {
      visible: String(row.finding.snippet || "") !== ""
      width: row.width - row.leftPadding - row.rightPadding
      implicitHeight: code.implicitHeight + Style.space(12)
      height: implicitHeight
      radius: Style.cornerRadius
      color: Style.normalFillFor(root.fg, root.accent)
      clip: true

      Rectangle {
        width: Math.max(2, Style.space(2))
        height: parent.height
        color: row.tint
        opacity: 0.8
      }

      Row {
        id: code
        x: Style.space(12)
        y: Style.space(6)

        Text {
          textFormat: Text.PlainText
          text: row.parts.before
          color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.78)
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
        }
        Text {
          textFormat: Text.PlainText
          text: row.parts.match
          color: row.tint
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          font.bold: true
        }
        Text {
          textFormat: Text.PlainText
          text: row.parts.after
          color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.78)
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
        }
      }
    }
  }

  // Changes between the verified commit and HEAD: a summary, the files
  // touched, then the unified diff coloured like a terminal would.
  component DiffView: Column {
    id: diffView
    readonly property var info: root.diff && root.diff.ok ? root.diff : ({ files: [], lines: [], totalLines: 0, summary: "" })
    readonly property int fileLimit: 14
    readonly property int lineLimit: 320
    readonly property var shownLines: (info.lines || []).slice(0, lineLimit)

    width: parent ? parent.width : implicitWidth
    spacing: Style.space(8)
    leftPadding: Style.space(10)
    rightPadding: Style.space(2)
    readonly property real inner: width - leftPadding - rightPadding

    Column {
      width: diffView.inner
      spacing: Style.space(2)

      Repeater {
        model: (diffView.info.files || []).slice(0, diffView.fileLimit)
        RowLayout {
          required property var modelData
          width: diffView.inner
          spacing: Style.space(8)

          Text {
            textFormat: Text.PlainText
            Layout.preferredWidth: Style.space(44)
            horizontalAlignment: Text.AlignRight
            text: "+" + (Number(modelData.added) || 0)
            color: root.safeColor
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
          Text {
            textFormat: Text.PlainText
            Layout.preferredWidth: Style.space(44)
            horizontalAlignment: Text.AlignRight
            text: "−" + (Number(modelData.removed) || 0)
            color: root.dangerColor
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
          Text {
            textFormat: Text.PlainText
            Layout.fillWidth: true
            text: String(modelData.path || "")
            color: root.fg
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            elide: Text.ElideMiddle
          }
        }
      }
    }

    Rectangle {
      visible: diffView.shownLines.length > 0
      width: diffView.inner
      implicitHeight: diffLines.implicitHeight + Style.space(12)
      height: implicitHeight
      radius: Style.cornerRadius
      color: Style.normalFillFor(root.fg, root.accent)
      clip: true

      Column {
        id: diffLines
        y: Style.space(6)
        width: parent.width

        Repeater {
          model: diffView.shownLines
          Rectangle {
            id: diffLine
            required property var modelData
            readonly property string kind: Risk.diffKind(modelData)
            readonly property color ink: kind === "+" ? root.safeColor
              : kind === "-" ? root.dangerColor
              : kind === "@" ? root.infoColor
              : kind === "h" ? root.fg
              : root.dim
            width: diffLines.width
            implicitHeight: diffText.implicitHeight + Style.space(2)
            height: implicitHeight
            color: kind === "+" || kind === "-" ? Qt.rgba(ink.r, ink.g, ink.b, 0.11) : "transparent"

            Text {
              id: diffText
              textFormat: Text.PlainText
              x: Style.space(10)
              y: Style.space(1)
              width: parent.width - Style.space(20)
              text: String(diffLine.modelData === "" ? " " : diffLine.modelData)
              color: diffLine.ink
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              font.bold: diffLine.kind === "h"
              elide: Text.ElideRight
            }
          }
        }
      }
    }

    Text {
      textFormat: Text.PlainText
      visible: (Number(diffView.info.totalLines) || 0) > diffView.shownLines.length
      width: diffView.inner
      text: strings.t("diff.more").arg((Number(diffView.info.totalLines) || 0) - diffView.shownLines.length)
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }
}
