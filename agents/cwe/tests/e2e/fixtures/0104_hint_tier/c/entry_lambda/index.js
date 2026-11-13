const fs = require("fs");

exports.handler = async ({ filePath }) => {
  return { statusCode: 200, body: JSON.stringify({ exists: fs.existsSync(filePath) }) }; // EXPECT: finding check=cwe.input_validation.path_traversal
};
