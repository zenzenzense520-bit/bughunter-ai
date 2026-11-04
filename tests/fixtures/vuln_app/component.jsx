// Intentionally vulnerable sample for BugHunter SAST tests. Test data only.

function Widget(html) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
