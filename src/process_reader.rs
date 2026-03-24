use std::io::{self, BufRead, BufReader, Read};
use std::process::{Child, ChildStdout};

pub struct ProcessReader {
    pub child: Child,
    pub reader: BufReader<ChildStdout>,
}

impl Read for ProcessReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl BufRead for ProcessReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.reader.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt)
    }
}

impl Drop for ProcessReader {
    fn drop(&mut self) {
        let _ = self.child.wait(); // ensure process is reaped
    }
}