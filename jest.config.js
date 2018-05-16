module.exports = {
    moduleFileExtensions: ["ts", "tsx", "js"],
    transform: {
        "^.+\\.(ts|tsx)$": "<rootDir>/preprocessor.js"
    },
    testMatch: ["**/__tests__/*.+(ts|tsx|js)"],
    testPathIgnorePatterns: ["/node_modules/", "__helpers__"],
    coveragePathIgnorePatterns: ["/node_modules/", "__helpers__"],
    collectCoverage: true,
    collectCoverageFrom: ["src/**/*.ts"]
}
