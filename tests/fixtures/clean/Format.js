.pragma library

function pad(value) {
  return value < 10 ? "0" + value : String(value)
}

function seconds(date) {
  return pad(date.getSeconds()) + "s"
}
