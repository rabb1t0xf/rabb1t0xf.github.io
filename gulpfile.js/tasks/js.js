#!/usr/bin/env node

"use strict";

const { src, dest, watch, series, parallel} = require('gulp');

const concat = require('gulp-concat');
const rename = require("gulp-rename");
const uglify = require('gulp-uglify');
const insert = require('gulp-insert');
const fs = require('fs');

//new const
const sass = require('gulp-sass')(require('sass'));
const cssnano = require('gulp-cssnano');
const prefix = require('gulp-autoprefixer');




const JS_SRC = '_javascript';
const JS_DEST = `assets/js/dist`;


/**
 * Compile and minify sass
 */
function stylesAddon() {
  return src([ '_sass/addon/*.scss', '_sass/colors/*.scss', '_sass/layout/*.scss', '_sass/*.scss'])
    .pipe(
      sass({
        includePaths: [ 'scss' ]
      })
    )
    .pipe(prefix([ 'last 3 versions', '> 1%', 'ie 8' ], { cascade: true }))
    .pipe(rename('style.min.css'))
    .pipe(cssnano())
    .pipe(dest('_site/assets/css/'))
    .pipe(dest('assets/css'));
}

function stylesHomePage() {
    return src([ '_sass/homepage/*.scss'])
    .pipe(
      sass({
        includePaths: [ 'scss' ]
      })
    )
    .pipe(prefix([ 'last 3 versions', '> 1%', 'ie 8' ], { cascade: true }))
    .pipe(rename('main.min.css'))
    .pipe(cssnano())
    .pipe(dest('_site/assets/css/'))
    .pipe(dest('assets/css'));
}

function stylesHomePageVendors() {
  return src([ '_sass/homepage/vendors/*.css' ])
    .pipe(concat('vendors.min.css'))
    .pipe(cssnano())
    .pipe(dest('_site/assets/css/'))
    .pipe(dest('assets/css'));
}


/**
 * Compile and minify javascript
 */
function concatJs(files, output) {
  return src(files)
    .pipe(concat(output))
    .pipe(rename({ extname: '.min.js' }))
    .pipe(dest(JS_DEST));
}

function minifyJs() {
  return src(`${ JS_DEST }/*.js`)
    .pipe(insert.prepend(fs.readFileSync(`${ JS_SRC }/copyright`, 'utf8')))
    .pipe(uglify({output: {comments: /^!|@preserve|@license|@cc_on/i}}))
    .pipe(dest(JS_DEST));
}

const commonsJs = () => {
  return concatJs(`${JS_SRC}/commons/*.js`, 'commons');
};

const homeJs = () => {
  return concatJs([
      `${JS_SRC}/commons/*.js`,
      `${JS_SRC}/utils/timeago.js`
    ],
    'home'
  );
};

const postJs = () => {
  return concatJs([
      `${JS_SRC}/commons/*.js`,
      `${JS_SRC}/utils/img-extra.js`,
      `${JS_SRC}/utils/timeago.js`,
      `${JS_SRC}/utils/checkbox.js`,
      `${JS_SRC}/utils/clipboard.js`,
      // 'smooth-scroll.js' must be called after ToC is ready
      `${JS_SRC}/utils/smooth-scroll.js`
    ], 'post'
  );
};

const categoriesJs = () => {
  return concatJs([
      `${JS_SRC}/commons/*.js`,
      `${JS_SRC}/utils/category-collapse.js`
    ], 'categories'
  );
};

const pageJs = () => {
  return concatJs([
      `${JS_SRC}/commons/*.js`,
      `${JS_SRC}/utils/checkbox.js`,
      `${JS_SRC}/utils/img-extra.js`,
      `${JS_SRC}/utils/clipboard.js`,
      `${JS_SRC}/utils/smooth-scroll.js`
    ], 'page'
  );
};

const miscJs = () => {
  return concatJs([
      `${JS_SRC}/commons/*.js`,
      `${JS_SRC}/utils/locale-datetime.js`
    ], 'misc'
  );
};

/**
 * homePage
 */
function scripts() {
  return src([ '_js/app.js' ])
    .pipe(rename('app.min.js'))
    .pipe(uglify())
    .pipe(dest('_site/assets/js'))
    .pipe(dest('assets/js'));
}

function scriptsVendors() {
  return src([ '_js/vendors/*.js' ])
    .pipe(concat('vendors.min.js'))
    .pipe(uglify())
    .pipe(dest('_site/assets/js'))
    .pipe(dest('assets/js'));
}

// GA pageviews report
const pvreportJs = () => {
  return concatJs(`${JS_SRC}/utils/pageviews.js`, 'pvreport');
};

const buildJs = parallel(
  commonsJs, 
  homeJs, 
  postJs, 
  categoriesJs, 
  pageJs, 
  miscJs, 
  pvreportJs,
  scripts,
  scriptsVendors
);

const buildScss = parallel(
  stylesAddon,
  stylesHomePage,
  stylesHomePageVendors
);

exports.build = series(buildJs, minifyJs, buildScss);

exports.liveRebuild = () => {
  buildJs();

  watch([
      `${ JS_SRC }/commons/*.js`,
      `${ JS_SRC }/utils/*.js`
    ],
    buildJs
  );
};
