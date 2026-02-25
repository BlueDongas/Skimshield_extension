const path = require('path');
const webpack = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');
const ForkTsCheckerWebpackPlugin = require('fork-ts-checker-webpack-plugin');

module.exports = (env, argv) => {
  const isProduction = argv.mode === 'production';

  return {
    mode: isProduction ? 'production' : 'development',
    devtool: isProduction ? 'source-map' : 'inline-source-map',

    entry: {
      'content/index': './src/presentation/content/index.ts',
      'content/injected': './src/presentation/content/injected.ts',
      'background/index': './src/presentation/background/index.ts',
      'popup/popup': './src/presentation/popup/popup.ts'
    },

    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name].js',
      clean: true
    },

    module: {
      rules: [
        {
          test: /\.ts$/,
          use: [
            {
              loader: 'ts-loader',
              options: {
                transpileOnly: true,
                compilerOptions: { module: 'ES2022' }
              }
            }
          ],
          exclude: /node_modules/
        },
        {
          test: /\.css$/,
          use: ['style-loader', 'css-loader']
        }
      ]
    },

    resolve: {
      extensions: ['.ts', '.js'],
      alias: {
        '@domain': path.resolve(__dirname, 'src/domain'),
        '@application': path.resolve(__dirname, 'src/application'),
        '@infrastructure': path.resolve(__dirname, 'src/infrastructure'),
        '@presentation': path.resolve(__dirname, 'src/presentation'),
        '@shared': path.resolve(__dirname, 'src/shared'),
        '@di': path.resolve(__dirname, 'src/di')
      }
    },

    plugins: [
      new webpack.DefinePlugin({
        __PROXY_API_URL__: JSON.stringify(process.env.PROXY_API_URL || undefined)
      }),
      new ForkTsCheckerWebpackPlugin({
        typescript: {
          configFile: path.resolve(__dirname, 'tsconfig.json'),
          diagnosticOptions: { semantic: true, syntactic: true }
        }
      }),
      new CopyPlugin({
        patterns: [
          { from: 'manifest.json', to: '.' },
          { from: 'src/presentation/popup/popup.html', to: 'popup/' },
          { from: 'src/presentation/popup/popup.css', to: 'popup/' },
          { from: 'src/assets', to: 'assets', noErrorOnMissing: true }
        ]
      })
    ],

    optimization: {
      minimize: isProduction,
      splitChunks: {
        chunks(chunk) {
          // content script와 background(service worker)는 단일 파일로 빌드
          return chunk.name === 'popup/popup';
        },
        cacheGroups: {
          vendor: {
            test: /[\\/]node_modules[\\/]/,
            name: 'shared/vendor',
            chunks(chunk) {
              // popup만 vendor 청크 분리
              return chunk.name === 'popup/popup';
            }
          }
        }
      }
    }
  };
};
