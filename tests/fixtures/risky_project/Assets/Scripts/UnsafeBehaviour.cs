using System.Diagnostics;
using UnityEngine;

public class UnsafeBehaviour : MonoBehaviour
{
    void Start()
    {
        Process.Start("/bin/bash", "-c 'echo risk'");
    }
}
