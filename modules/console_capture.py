"""
Módulo de Captura de Consola
Captura toda la salida de consola durante el escaneo
"""

import sys
import io
from contextlib import contextmanager
from typing import Optional
from modules.scan_manager import ScanManager

class ConsoleCapture:
    """Capturador de salida de consola"""
    
    def __init__(self, scan_manager: ScanManager):
        self.scan_manager = scan_manager
        self.original_stdout = None
        self.original_stderr = None
        self.captured_output = io.StringIO()
        self.is_capturing = False
    
    def start_capture(self):
        """Iniciar captura de consola"""
        if self.is_capturing:
            return
        
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        
        # Crear capturador que escribe tanto a consola como al buffer
        self.captured_output = io.StringIO()
        
        class TeeOutput:
            def __init__(self, *outputs):
                self.outputs = outputs
            
            def write(self, text):
                for output in self.outputs:
                    output.write(text)
                    output.flush()
            
            def flush(self):
                for output in self.outputs:
                    output.flush()
        
        # Configurar salida teed
        sys.stdout = TeeOutput(self.original_stdout, self.captured_output)
        sys.stderr = TeeOutput(self.original_stderr, self.captured_output)
        
        self.is_capturing = True
    
    def stop_capture(self) -> str:
        """Detener captura y devolver salida capturada"""
        if not self.is_capturing:
            return ""
        
        # Restaurar salida original
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        
        # Obtener salida capturada
        captured_text = self.captured_output.getvalue()
        
        # Guardar en archivo
        if self.scan_manager and captured_text.strip():
            self.scan_manager.save_console_output(captured_text)
        
        self.is_capturing = False
        return captured_text
    
    @contextmanager
    def capture_context(self):
        """Context manager para captura automática"""
        self.start_capture()
        try:
            yield
        finally:
            self.stop_capture()
    
    def get_captured_output(self) -> str:
        """Obtener salida capturada actual"""
        if self.is_capturing:
            return self.captured_output.getvalue()
        return ""
