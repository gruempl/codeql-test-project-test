// src/utils/asyncHandler.js
export default function asyncHandler(fn) {
  return function (req, res, next) {
    // fn may return a promise; forward rejections to next()
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
