const { WranglerJsCompatWebpackPlugin } = require("wranglerjs-compat-webpack-plugin")

module.exports = {
  mode: "production",
  plugins: [new WranglerJsCompatWebpackPlugin()],
}
