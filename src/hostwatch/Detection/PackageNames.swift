import Foundation

// Lookalike names (ADR 0024, layer 4): a name one edit from a well-known package of the same ecosystem is how
// typosquats and names an AI made up get installed. A sign, never proof: asked about for AI agents, a story for you,
// refused only in Strict. Offline: a short built-in list plus the packages your own projects use.

enum PackageNames {
    /// The package `name` looks like, nil when it looks like none (or is one of them).
    static func lookalike(_ name: String, _ eco: PackageEcosystem, known: Set<String>) -> String? {
        let n = eco.normalize(name)
        guard n.count >= 4, !known.contains(n) else { return nil }
        let bare = squeeze(n)
        for k in known where k.count >= 4 && abs(k.count - n.count) <= 2 {
            if squeeze(k) == bare { return k }                         // react-dom / reactdom / react_dom
            if n.count >= 5, k.count >= 5, oneEdit(n, k) { return k }
        }
        return nil
    }

    private static func squeeze(_ s: String) -> String { s.filter { !"-_.".contains($0) } }

    /// One insertion, deletion, substitution, or swap of neighbours.
    static func oneEdit(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        if x == y { return false }
        if x.count == y.count {
            let diff = x.indices.filter { x[$0] != y[$0] }
            if diff.count == 1 { return true }
            return diff.count == 2 && diff[1] == diff[0] + 1 && x[diff[0]] == y[diff[1]] && x[diff[1]] == y[diff[0]]
        }
        guard abs(x.count - y.count) == 1 else { return false }
        let (long, short) = x.count > y.count ? (x, y) : (y, x)
        var i = 0
        while i < short.count, long[i] == short[i] { i += 1 }
        return Array(long[(i + 1)...]) == Array(short[i...])
    }

    /// The names every developer types, per ecosystem: the most downloaded, from memory of the registries' top
    /// lists. Your projects' own packages are added at run time (`PackageGuard.known`).
    static let builtIn: [PackageEcosystem: [String]] = [
        .npm: """
        react react-dom react-router react-router-dom next vue nuxt svelte angular @angular/core express koa fastify
        lodash underscore axios node-fetch request chalk debug commander yargs minimist inquirer ora moment dayjs
        date-fns uuid nanoid classnames prop-types redux react-redux zustand mobx rxjs typescript ts-node tslib
        webpack webpack-cli vite rollup esbuild parcel babel-core @babel/core @babel/preset-env eslint prettier jest
        mocha chai sinon vitest cypress playwright puppeteer jquery bootstrap tailwindcss postcss autoprefixer sass
        less styled-components @emotion/react socket.io ws body-parser cors dotenv cross-env nodemon pm2 concurrently
        rimraf mkdirp glob fs-extra semver colors cheerio jsonwebtoken bcrypt bcryptjs passport mongoose mongodb
        sequelize prisma @prisma/client pg mysql mysql2 redis ioredis sqlite3 knex graphql apollo-server
        @apollo/client electron electron-builder zod yup joi ajv qs querystring form-data formidable multer sharp
        jimp three d3 chart.js highlight.js marked markdown-it core-js regenerator-runtime async bluebird
        event-stream through2 readable-stream safe-buffer buffer process util path-browserify crypto-js
        node-sass sass-loader css-loader style-loader file-loader url-loader html-webpack-plugin terser
        uglify-js clean-css husky lint-staged nx turbo lerna yarn pnpm npm npx serve http-server
        """.split(whereSeparator: \.isWhitespace).map(String.init),
        .pypi: """
        requests urllib3 numpy pandas scipy matplotlib seaborn scikit-learn tensorflow torch torchvision keras flask
        django fastapi uvicorn gunicorn starlette pydantic sqlalchemy alembic psycopg2 psycopg2-binary pymysql redis
        celery boto3 botocore awscli s3transfer google-cloud-storage azure-storage-blob openai anthropic langchain
        transformers huggingface-hub tokenizers datasets pillow opencv-python beautifulsoup4 lxml html5lib selenium
        scrapy httpx aiohttp websockets pyyaml toml tomli python-dateutil pytz six setuptools wheel pip virtualenv
        pytest pytest-cov tox nose coverage mock black flake8 pylint mypy isort ruff click typer rich tqdm colorama
        jinja2 markupsafe werkzeug itsdangerous cryptography pyopenssl paramiko bcrypt pyjwt jsonschema attrs
        certifi charset-normalizer idna packaging pyparsing docutils sphinx matplotlib-inline ipython jupyter
        notebook jupyterlab ipykernel numba cython protobuf grpcio pyarrow polars networkx sympy statsmodels
        xgboost lightgbm catboost plotly dash streamlit gradio discord.py python-telegram-bot tweepy pygame
        """.split(whereSeparator: \.isWhitespace).map(String.init),
        .crates: """
        serde serde_json serde_derive tokio rand clap anyhow thiserror log env_logger tracing regex reqwest hyper
        futures async-trait chrono lazy_static once_cell itertools syn quote proc-macro2 bytes libc bitflags
        """.split(whereSeparator: \.isWhitespace).map(String.init),
        .rubygems: """
        rails rack rake bundler nokogiri devise puma sidekiq rspec rubocop pry activesupport activerecord json
        """.split(whereSeparator: \.isWhitespace).map(String.init),
    ]
}
